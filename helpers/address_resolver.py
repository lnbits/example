import dns.resolver
import dns.message
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
from http import HTTPStatus
from fastapi import HTTPException
from loguru import logger

# DNSSEC-validating resolvers — both validate the full chain and set AD flag
DNSSEC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Authentic Data flag (RFC 4035) — set by resolver when DNSSEC validation passed
AD_FLAG = 0x0020


def _query_txt_with_dnssec(qname: str) -> tuple[list[str], bool]:
    qname_obj = dns.name.from_text(qname)
    request = dns.message.make_query(qname_obj, dns.rdatatype.TXT, want_dnssec=True)

    last_error = None
    for nameserver in DNSSEC_RESOLVERS:
        try:
            try:
                response = dns.query.tcp(request, nameserver, timeout=10)
            except Exception:
                response = dns.query.udp(request, nameserver, timeout=10)

            dnssec_valid = bool(response.flags & AD_FLAG)

            records = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rdata in rrset:
                        records.append("".join(s.decode() for s in rdata.strings))

            if records:
                return records, dnssec_valid

            # NXDOMAIN → domain itself doesn't exist
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()

            # ★ NEW: resolver answered successfully (NOERROR) but there are no
            # TXT records → the name has no BIP-353 record. This is a definitive
            # "not found", NOT a resolver failure. Raise NoAnswer so the caller
            # maps it to 404 instead of falling through to "all resolvers failed".
            if response.rcode() == dns.rcode.NOERROR:
                raise dns.resolver.NoAnswer(response=response)

            # Any other RCODE (SERVFAIL etc.) → try the next resolver
            last_error = Exception(f"RCODE {response.rcode()} from {nameserver}")
            continue

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = e
            logger.warning(f"DNSSEC query to {nameserver} failed: {e}, trying next")
            continue

    raise Exception(f"All DNSSEC resolvers failed. Last error: {last_error}")


def bip353_resolve(address: str) -> dict:
    try:
        user, domain = address.strip().split("@")
    except ValueError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid BIP353 address format. Expected user@domain.com",
        )

    dns_domain = f"{user}.user._bitcoin-payment.{domain}"

    try:
        records, dnssec_valid = _query_txt_with_dnssec(dns_domain)

        if not records:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=f"No TXT record found for {dns_domain}",
            )

        if not dnssec_valid:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"DNSSEC validation failed for {dns_domain}. "
                    "The domain must have valid DNSSEC signatures. "
                    "Resolving this address would be unsafe."
                ),
            )

        result = records[0]

        if not result.startswith("bitcoin:"):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"TXT record does not contain a valid bitcoin: URI: {result}",
            )

        # logger.info(f"BIP353 resolved {address} → {result} (DNSSEC validated)")
        return {
            "address": address,
            "dns_domain": dns_domain,
            "result": result,
            "dnssec": True,
        }

    except HTTPException:
        raise
    except dns.resolver.NXDOMAIN:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Domain not found: {dns_domain}",
        )
    except dns.resolver.NoAnswer:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No TXT record found for {address}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"DNS resolution failed: {str(exc)}",
        )
