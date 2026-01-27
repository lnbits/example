<a href="https://lnbits.com" target="_blank" rel="noopener noreferrer">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://i.imgur.com/QE6SIrs.png">
    <img src="https://i.imgur.com/fyKPgVT.png" alt="LNbits" style="width:280px">
  </picture>
</a>

[![License: MIT](https://img.shields.io/badge/License-MIT-success?logo=open-source-initiative&logoColor=white)](./LICENSE)
[![Built for LNbits](https://img.shields.io/badge/Built%20for-LNbits-4D4DFF?logo=lightning&logoColor=white)](https://github.com/lnbits/lnbits)

# LNbits Extension Starter Template

A **starter template for developers** to build new LNbits extensions with a clean, well-structured foundation.

This repository provides a ready-to-use extension skeleton that follows LNbits conventions and best practices, making it easier to build, test, and maintain custom extensions.

[![Watch the video](https://img.youtube.com/vi/aRTRYcNwqj0/maxresdefault.jpg)](https://www.youtube.com/watch?v=aRTRYcNwqj0)

## Purpose

This template is designed to:

- Serve as a **clonable base structure** for new LNbits extensions
- Demonstrate **recommended LNbits extension patterns**
- Reduce setup time for new extension projects
- Encourage consistency across the LNbits extension ecosystem

It is the **recommended starting point** if you want to develop your own LNbits extension with proper structure and conventions.

## Features

The template includes:

- Example extension layout (backend + frontend)
- Sample database models
- Example API endpoints
- Configuration and metadata files
- Support for **symbolic linking** to simplify local development
- Clear separation of logic, views, and API routes

All components are intentionally minimal and meant to be adapted or extended.

## API Example

If your extension exposes API endpoints, document them clearly.  
Below is a simple example request pattern:

```
curl -H "Content-type: application/json" \
  -H "X-Api-Key: YOUR_WALLET_ADMIN_OR_INVOICE_KEY" \
  -X POST https://YOUR-LNBITS/YOUR-EXTENSION/api/v1/example \
  -d '{"amount": 100, "memo": "example"}'
```

Replace the endpoint, payload, and permissions according to your extension logic.

## Development Notes

* This template supports **symbolic linking** for local LNbits development setups
* Intended for developers familiar with LNbits and its extension system
* You are expected to modify, remove, or extend all example logic

### Important

If you are using **LLMs to generate code**, please make sure to follow the official LNbits instructions when configuring your model to avoid insecure or incompatible output.

## Learn More

* LNbits core repository: [https://github.com/lnbits/lnbits](https://github.com/lnbits/lnbits)
* Extension documentation: [https://github.com/lnbits/lnbits/wiki/LNbits-Extensions](https://github.com/lnbits/lnbits/wiki/LNbits-Extensions)
* Official website: [https://lnbits.com](https://lnbits.com)

## Powered by LNbits

LNbits is a free and open-source Lightning accounts system.

[![Visit LNbits Shop](https://img.shields.io/badge/Visit-LNbits%20Shop-7C3AED?logo=shopping-cart\&logoColor=white\&labelColor=5B21B6)](https://shop.lnbits.com/)
[![Try myLNbits SaaS](https://img.shields.io/badge/Try-myLNbits%20SaaS-2563EB?logo=lightning\&logoColor=white\&labelColor=1E40AF)](https://my.lnbits.com/login)
