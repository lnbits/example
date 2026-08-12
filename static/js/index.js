window.app = Vue.createApp({
  el: '#vue',
  mixins: [window.windowMixin],
  data() {
    return {
      blindbit: {
        url: ''        
      },  
      showScanDialog: false,
      scanDialog: {
        wallet: null,
        lastHeight: 1,
        chainTip: null,
        oracleTip: null,
        loading: false
      },
      scanProgress: {
        active: false,
        current: 0,
        total: 0,
        found: 0,
        walletId: null
      },   
      config: {sats_denominated: true},
      showBip353Dialog: false,
      bip353Address: '',
      bip353Result: '',
      bip353Loading: false,
      qrCodeDialog: {
        show: false,
        data: null
      },
      showBroadcastConfirm: false,
      sendTxFee: 0,
      sendTxAmount: 0,
      sendTxVsize: 0,
      ...tables,
      ...tableData,
      walletAccounts: [],            
      utxosFilter: '',
      network: null,
      lastScanResult: null,
      showSendDialog: false,
      sendWallet: null,
      sendUtxos: [],
      sendForm: {
        recipient: '',
        amount: 0,
        feeRate: 1.0,
        memo: '',
        useAllUtxos: false
      },
      sendLoading: false,
      broadcastLoading: false,
      sendTxResult: null      
    }
  },
  computed: {
    sendSelectedTotal: function () {
        return this.sendUtxos
    .filter(u => u.selected)
    .reduce((sum, u) => sum + (u.amount || 0), 0)
  },
    canBuildTx: function () {
      const hasRecipient = !!this.sendForm.recipient
      const hasUtxos = this.sendUtxos.some(u => u.selected) || this.sendForm.useAllUtxos
      const hasAmount = this.sendForm.useAllUtxos || this.sendForm.amount > 0
      const hasFee = this.sendForm.feeRate > 0
      return hasRecipient && hasUtxos && hasAmount && hasFee && !this.sendLoading
    },
    mempoolBaseUrl: function () {      
      if (!this.config || !this.config.isLoaded) return 'https://mempool.space'
      try {
        const endpoint = this.config.mempool_url || 'https://mempool.space'        
        const withProtocol = endpoint.startsWith('http')
          ? endpoint
          : `https://${endpoint}`
        const url = new URL(withProtocol)
        let base = `${url.protocol}//${url.hostname}`
        if (url.port) base += `:${url.port}`              
        return base.replace(/\/$/, '') 
        } catch (e) {
            return 'https://mempool.space'
          }        
    },
    selectedUtxoLabels: function () {
      if (!this.sendUtxos || !this.sendUtxos.length) return []
      const labels = [
        ...new Set(
          this.sendUtxos
            .filter(u => u.selected && u.label)
            .map(u => u.label)
        )
      ]
    return labels
},   
  },

  methods: {
    fetchUtxos: async function (wallet) {      
      if (!wallet || !wallet.id) return
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/utxos?wallet_id=${wallet.id}`,
          this.g.user.wallets[0].inkey
        )

        const mappedUtxos = (data.utxos || []).map(u => ({
          txid: u.txid,
          amount: u.amount,
          vout: u.vout ?? 0,
          utxo_state: u.utxo_state,
          timestamp: u.timestamp,
          label: u.label,
          priv_key_tweak: u.priv_key_tweak,
          pub_key: u.pub_key,
          wallet: wallet.id,
          editingLabel: false,            // ← UI state
          labelDraft: ''                  // ← UI state
        }))

        this.utxos.data = mappedUtxos
        this.utxos.total = mappedUtxos
          .filter(u => u.utxo_state === 'unspent')
          .reduce((total, u) => total + (u.amount || 0), 0)

        this.lastScanResult = {
          utxos: mappedUtxos,
          timestamp: Date.now()
        }

        this.$q.notify({
          type: 'positive',
          message: `Loaded ${mappedUtxos.length} UTXO(s) from DB.`,
          timeout: 5000
        })
        this.tab = 'utxos'
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      }
    },
    scanWallet: async function (wallet) {
      if (!wallet || !wallet.id) return
      if (!this.config.blindbit_url) {
        this.$q.notify({
          type: 'warning',
          message: 'BlindBit Oracle URL not configured. Open Settings to set it.',
          timeout: 10000
        })
        return
      }
      try {
      const {data: freshWallet} = await LNbits.api.request(
        'GET',
        `/siLNt/api/v1/wallet/${wallet.id}`,
        this.g.user.wallets[0].inkey
      )
      wallet = mapWalletAccount(freshWallet)
    } catch (err) {
      // fall back to cached wallet if fetch fails
      logger.warning('Could not refresh wallet from DB, using cached data')
    }
        // Open dialog immediately with known data
    this.scanDialog.wallet = wallet
    this.scanDialog.lastHeight = wallet.last_scan_height || wallet.last_height
    this.scanDialog.chainTip = null
    this.scanDialog.oracleTip = null  
    this.scanDialog.loading = true
    this.showScanDialog = true

    // Fetch chain tip in background
    try {
      const response = await LNbits.api.request(
        'GET',
        '/siLNt/api/v1/oracle/tip',
        this.g.user.wallets[0].inkey
      )            
      const tip = response.data?.height ?? response.data?.block_height
      this.scanDialog.chainTip = tip
      this.scanDialog.chainTip = tip
      } catch (err) {
        this.scanDialog.chainTip = null
        this.$q.notify({
          type: 'warning',
          message: 'Could not fetch chain tip from BlindBit Oracle.',
          timeout: 5000
        })
      } finally {
        this.scanDialog.loading = false
      }
      },
    startScan: async function () {
      const wallet = this.scanDialog.wallet
      this.showScanDialog = false
       // Start progress polling
      this.scanProgress.active = true
      this.scanProgress.current = 0
      this.scanProgress.total = this.scanDialog.chainTip - this.scanDialog.lastHeight
      this.scanProgress.found = 0
      this.scanProgress.walletId = wallet.id
      const pollInterval = setInterval(async () => {
        try {
          const {data} = await LNbits.api.request(
            'GET',
            `/siLNt/api/v1/wallet/${wallet.id}/scan/progress`,
            this.g.user.wallets[0].inkey
          )
          this.scanProgress.current = data.current || 0
          this.scanProgress.total = data.total || this.scanProgress.total
          this.scanProgress.found = data.found || 0
          if (!data.active) {
            clearInterval(pollInterval)
            this.scanProgress.active = false
          }
        } catch (e) {
          // ignore poll errors
        }
      }, 1000)  // poll every second
      try {        
        const {data} = await LNbits.api.request(
          'POST',
          `/siLNt/api/v1/wallet/${wallet.id}/scan`,
          this.g.user.wallets[0].inkey,
          {
            from_height: this.scanDialog.lastHeight,
            to_height: this.scanDialog.chainTip
          }
        )
        clearInterval(pollInterval)
        this.scanProgress.active = false
        this.$q.notify({
          type: 'positive',
          message: `Scan complete. ${data.utxos_found} Unspent UTXO(s) found across ${data.blocks_scanned} blocks.`,
          timeout: 8000
        })
        await this.fetchUtxos(wallet)
      } catch (err) {
         clearInterval(pollInterval)
        this.scanProgress.active = false
        LNbits.utils.notifyApiError(err)
      }
    },
    stopScan: async function () {
      if (!this.scanProgress.walletId) return
      this.scanProgress.stopping = true
      try {
        await LNbits.api.request(
          'POST',
          `/siLNt/api/v1/wallet/${this.scanProgress.walletId}/scan/stop`,
          this.g.user.wallets[0].inkey
        )
        this.$q.notify({
          type: 'info',
          message: 'Stop requested — scan will halt at the next block.',
          timeout: 5000
        })
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.scanProgress.stopping = false
      }
    },
    resolveBip353: async function () {
      if (!this.bip353Address) return
      this.bip353Loading = true
      this.bip353Result = ''
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/bip353/resolve?address=${encodeURIComponent(this.bip353Address)}`,
          this.g.user.wallets[0].inkey
        )

        // Strip bitcoin:?sp= / bitcoin:?lno= / lno= prefixes
        let result = data.result || ''        
        result = result.replace(/^bitcoin:\?sp=/i, '')
        result = result.replace(/^bitcoin:\?lno=/i, '')
        result = result.replace(/^lno=/i, '')
        result = result.replace(/^sp=/i, '')
        this.bip353Result = result.trim()        
        this.$q.notify({
          type: 'positive',
          message: `BIP353 resolved for ${this.bip353Address}`,
          timeout: 5000
        })
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.bip353Loading = false
      }
    },
    copyText: function (text) {
      Quasar.copyToClipboard(text).then(() => {
        this.$q.notify({
          message: 'Copied to clipboard!',
          position: 'bottom'
        })
      })
    },        
    clearUtxosForWallet: function (walletId) {
      // Remove UTXOs belonging to deleted wallet
      const before = this.utxos.data.length
      this.utxos.data = this.utxos.data.filter(u => u.wallet !== walletId)
      
      // Recalculate total from remaining unspent UTXOs
      this.utxos.total = this.utxos.data
        .filter(u => u.utxo_state === 'unspent')
        .reduce((sum, u) => sum + (u.amount || 0), 0)

      // If nothing was filtered (wallet field missing), clear everything
      if (this.utxos.data.length === before) {
        this.utxos.data = []
        this.utxos.total = 0
      }

      this.lastScanResult = null

      this.$q.notify({
        type: 'info',
        message: 'UTXOs cleared for deleted wallet.',
        timeout: 5000
      })
    },
    openSendDialog: function (wallet) {
      this.sendWallet = wallet
      this.sendTxResult = null
      this.sendTxAmount = 0
      this.sendTxVsize = 0
      this.sendForm = {
        recipient: '',
        amount: 0,
        feeRate: 1,
        memo: '',
        useAllUtxos: false
      }
      // Load unspent UTXOs for this wallet
      this.sendUtxos = (this.utxos.data || [])
        .filter(u => u.utxo_state === 'unspent' && u.wallet === wallet.id)
        .map(u => ({ ...u, selected: false, label: u.label || '' }))
      this.showSendDialog = true
    },

    onUseAllUtxos: function (val) {
      if (val) {
        this.sendUtxos.forEach(u => { u.selected = true })
        this.sendForm.amount = this.sendSelectedTotal
      } else {
        this.sendUtxos.forEach(u => { u.selected = false })
        this.sendForm.amount = 0
      }
    },
    buildTransaction: async function () {
      this.sendLoading = true
      this.sendTxResult = null
      try {
        const selectedUtxos = this.sendUtxos.filter(u => u.selected)       
        const {data} = await LNbits.api.request(
          'POST',
          '/siLNt/api/v1/tx/build',
          this.g.user.wallets[0].adminkey,
          {
            wallet_id: this.sendWallet.id,
            recipient: this.sendForm.recipient,
            amount: this.sendForm.useAllUtxos ? this.sendSelectedTotal : this.sendForm.amount,
            fee_rate: Math.max(0.1, parseFloat(this.sendForm.feeRate)) || 0.1,
            memo: this.sendForm.memo,
            utxos: selectedUtxos.map(u => ({
              txid: u.txid,
              amount: u.amount,
              label: u.label,
              vout: u.vout || 0,
              priv_key_tweak: u.priv_key_tweak,
              pub_key: u.pub_key
            }))
          }
        )        
        this.sendTxResult = data.psbt || data.tx_hex || JSON.stringify(data)
        this.sendTxFee = data.fee
        this.sendTxAmount = data.amount      // ← store actual amount from backend
        this.sendTxVsize = data.vsize        // ← store vsize for display
        this.$q.notify({
          type: 'positive',
          message: 'Transaction built successfully.',
          timeout: 5000
        })
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.sendLoading = false
      }
    },
    broadcastTransaction: async function () {
      this.broadcastLoading = true
      try {
        const {data} = await LNbits.api.request(
          'POST',
          '/siLNt/api/v1/tx/broadcast',
          this.g.user.wallets[0].adminkey,
          { tx_hex: this.sendTxResult,
            wallet_id: this.sendWallet?.id,
            spent_txids: this.sendUtxos
              .filter(u => u.selected)
              .map(u => u.txid)
           }
        )
        const txid = data.txid

        const mempoolUrl = `${this.mempoolBaseUrl}/tx/${txid}`
        // Mark unconfirmed_spent UTXOs in the local list
        const selectedTxids = this.sendUtxos
          .filter(u => u.selected)
          .map(u => u.txid)

         this.utxos.data = this.utxos.data.map(u =>
          selectedTxids.includes(u.txid)
            ? { ...u, utxo_state: 'unconfirmed_spent' }
            : u
        )
        // Add the broadcasted transaction as a pending entry in the UTXO list
        this.utxos.data.push({
          txid: txid,
          vout: 0,
          amount: 0,
          utxo_state: 'broadcasted',
          timestamp: Math.floor(Date.now() / 1000),
          wallet: this.sendWallet?.id,
          priv_key_tweak: '',
          pub_key: '',
          label: null,
          _broadcasted: true
        })
         // Recalculate total
        this.utxos.total = this.utxos.data
        .filter(u => u.utxo_state === 'unspent')
        .reduce((sum, u) => sum + (u.amount || 0), 0)

        this.$q.notify({
          type: 'positive',
          message: `Transaction broadcast! View on mempool`,
          actions: [{
            // label: txid.substring(0, 16) + '...',
            lable: 'View on Mempool',
            color: 'white',
            handler: () => window.open(mempoolUrl, '_blank')
          }],
          timeout: 15000
        })
        this.showBroadcastConfirm = false  
        this.showSendDialog = false
        this.sendTxResult = null
        this.sendTxFee = 0
        this.tab = 'utxos'
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.broadcastLoading = false
      }
    },
    confirmBroadcast: function () {
      this.showBroadcastConfirm = true
    },                   
  }, 
  created: async function () {       
  }
})
