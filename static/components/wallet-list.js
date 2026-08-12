window.app.component('wallet-list', {
  name: 'wallet-list',
  template: '#wallet-list',
  delimiters: ['${', '}'],

  props: [
    'adminkey',
    'inkey',
    'sats-denominated',
    // 'addresses',
    'network',
    'scannedUtxos'   
  ],
  emits: ['accounts-update', 'fetch-utxos', 'scan-wallet', 'clear-utxos', 'open-bip353', 'send-wallet'],
  data: function () {
    return {
      thrillaUrl: 'https://signet.thrilla.me',   // or pull from server config
      walletAccounts: [],
      address: {},      
      formDialog: {
        show: false,                
        data: {
          title: '',          
          hr_address: '',
          last_height: '',
          network: 'mainnet'          
        }
      },
      updateDialog: {
        show: false,                
        data: {
          title: '',          
          hr_address: '',
          last_height: ''          
        }
      },
      qrDialog: {
        show: false,
        address: ''
      },
      addressDialog: {
        show: false,
        wallet: null,
        addresses: [],
        generating: false
      },
      bip353Valid: true,          
      showCreating: false,
      showUpdating: false,
      walletsTable: {
        columns: [          
          {name: 'sp_address', align: 'left', label: 'SP Address', field: 'sp_address'},                  
          {
            name: 'title',
            align: 'left',
            label: 'Title',
            field: 'title'
          },                    
          {
            name: 'hr_address',
            align: 'left',
            label: 'BIP353 Address',
            field: 'hr_address'
          },
          {
            name: 'last_height',
            align: 'left',
            label: 'Height',
            field: 'last_height'
          },
          {
            name: 'balance',
            align: 'left',
            label: 'Balance',
            field: 'balance'
          }       
        ],
        pagination: {
          rowsPerPage: 10
        }
      }      
    }
  },  
  watch: {
      scannedUtxos: {
        deep: true,
        handler(result) {
          if (!result || !result.utxos || !result.utxos.length) return

          // Get wallet_id from the UTXOs themselves
          const walletId = result.utxos[0]?.wallet_id
          if (!walletId) return

          // Only update the specific wallet — not all wallets
          const wallet = this.walletAccounts.find(w => w.id === walletId)
          if (!wallet) return

          const newBalance = result.utxos
            .filter(u => u.utxo_state === 'unspent')
            .reduce((sum, u) => sum + (u.amount || 0), 0)

          if (newBalance === wallet.balance) return

          this.updateWalletBalance(wallet.id, newBalance)
          wallet.balance = newBalance
        }
      }
  },
  methods: {
    satBtc(val, showUnit = true) {
      return satOrBtc(val, showUnit, this.satsDenominated)
    },        
    addWalletAccount: async function () {
      this.showCreating = true
      const data = _.omit(this.formDialog.data, 'wallet')
      data.network = this.formDialog.data.network || this.network
      // Validate BIP353 hr_address if provided
      if (data.hr_address && data.hr_address.trim() !== '') {
        const valid = await this.validateBip353(data.hr_address)
        if (!valid) {
          this.showCreating = false
          return
        }
      }     
      data.mnemonic = CryptoJS.AES.encrypt(data.mnemonic, data.last_height).toString();            
      await this.createWalletAccount(data)      
      this.showCreating = false
    },
    updateWalletAccount: async function () {
      this.showUpdating = true
      const data = _.omit(this.updateDialog.data, 'wallet')
      data.network = this.network
      // Validate BIP353 hr_address if provided
      if (data.hr_address) {
        const valid = await this.validateBip353(data.hr_address)
        if (!valid) {
          this.showUpdating = false
          return
        }
      }          
      if (data.id) {
        await this.updateWalletDetails(data)
      }      
      this.showUpdating = false
    },
    createWalletAccount: async function (data) {
      try {             
        const response = await LNbits.api.request(
          'POST',
          '/siLNt/api/v1/wallet',
          this.inkey,
          data
        )        
        const r = response.data || {}

      this.formDialog.show = false
      await this.refreshWalletAccounts()

      // If keys were returned, show a one-time copy dialog
      if (r.scan_secret && r.spend_key) {
        const keysJson = JSON.stringify({
          wallet_id:   r.wallet_id,
          scan_secret: r.scan_secret,
          spend_key:   r.spend_key,
        }, null, 2)

        Quasar.Dialog.create({
          title: 'Wallet Keys — Save These Now',
          message:
            'Your wallet has been created. The keys below are shown ONCE and ' +
            'will NOT be stored on the server.\\n\\n' +
            'To use this wallet, open the Thrilla app, recover the wallet ' +
            'with your mnemonic, or paste these keys directly.\\n\\n' +
            'If you lose them, you\'ll need to re-import from the mnemonic.',
          html: false,
          message: `<pre style="background:#f5f5f5;padding:10px;border-radius:4px;
                          font-family:monospace;font-size:11px;overflow:auto">${keysJson}</pre>`,
          ok: {
            label: 'I have saved them',
            color: 'positive',
          },
          persistent: true,
        })

        Quasar.copyToClipboard(keysJson)
        this.$q.notify({
          type: 'positive',
          message: 'Wallet keys copied to clipboard. Save them somewhere safe.',
          timeout: 10000,
        })
      } else {
        this.$q.notify({
          type: 'positive',
          message: 'Silent Payment Wallet created.',
          timeout: 5000,
        })
      }
    } catch (error) {
      LNbits.utils.notifyApiError(error)
    }        
    },
    updateWalletDialog(walletAccountId) {
      var wallet = _.findWhere(this.walletAccounts, {id: walletAccountId})
      this.updateDialog.data = _.clone(wallet)      
      this.updateDialog.hr_address = this.updateDialog.data.hr_address
      this.updateDialog.last_height = this.updateDialog.data.last_height
      this.updateDialog.title = this.updateDialog.data.title
      this.updateDialog.show = true
      this.bip353Valid = true
    },
    updateWalletDetails: async function (data) {      
      try {        
        const response = await LNbits.api.request(
          'PUT',
          '/siLNt/api/v1/wallet/' + data.id,
          this.inkey,
          data
        )            
        this.walletAccounts.push(mapWalletAccount(response.data))
        this.updateDialog.show = false
        await this.refreshWalletAccounts()
        Quasar.Notify.create({
            type: 'positive',
            message: 'Wallet updated.'
      })
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }                
    },
    deleteWalletDialog: function (walletAccountId) {
      LNbits.utils
        .confirmDialog(
          'Are you sure you want to delete this wallet?'
        )
        .onOk(async () => {
          try {
            await LNbits.api.request(
              'DELETE',
              '/siLNt/api/v1/wallet/' + walletAccountId,
              this.inkey
            )
            this.walletAccounts = _.reject(this.walletAccounts, function (obj) {
              return obj.id === walletAccountId
            })
            await this.refreshWalletAccounts()
            this.$emit('clear-utxos',walletAccountId)
          } catch (error) {
            this.$q.notify({
              type: 'warning',
              message: 'Error while deleting wallet account. Please try again.',
              timeout: 10000
            })
          }
        })
    },
    getsiLNtWallets: async function () {      
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/wallet`,
          this.inkey
        )        
        return data
      } catch (error) {        
        this.$q.notify({
          type: 'warning',
          message: 'Failed to fetch wallets.',
          timeout: 10000
        })
        LNbits.utils.notifyApiError(error)
      }
      return []
    },
    refreshWalletAccounts: async function () {
      this.walletAccounts = []
      const wallets = await this.getsiLNtWallets()           
      // Load addresses for each wallet in parallel
      const walletsWithAddresses = await Promise.all(
        wallets.map(async w => {
          let addresses = []
          try {
            const {data} = await LNbits.api.request(
              'GET',
              `/siLNt/api/v1/wallet/${w.id}/addresses`,
              this.inkey
            )
            addresses = data.addresses || []
          } catch (e) {
            // ignore — wallet still loads without addresses
          }
          return {
            ...mapWalletAccount(w),
            expanded: false,
            addresses: addresses,
            loadingAddresses: false
          }
        })
      )
      this.walletAccounts = walletsWithAddresses     
      this.$emit('accounts-update', this.walletAccounts)
    },
    updateWalletBalance: async function (walletId, balance) {
      try {        
        await LNbits.api.request(
          'PUT',
          `/siLNt/api/v1/wallet/${walletId}`,
          this.inkey,
          { balance }
        )
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },
    validateBip353: async function (address) {
      // Basic email format check first
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(address)) {
        this.$q.notify({
          type: 'warning',
          message: 'BIP353 Address must be in email format (e.g. alice@domain.com)',
          timeout: 8000
        })
        // this.bip353Valid = false
        return false
      }
      try {
        await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/bip353/resolve?address=${encodeURIComponent(address)}`,
          this.inkey
        )
        this.$q.notify({
          type: 'positive',
          message: `BIP353 address verified: ${address}`,
          timeout: 5000
        })
        this.bip353Valid = true
        return true
      } catch (error) {
        this.$q.notify({
          type: 'negative',
          message: `BIP353 resolution failed for ${address} — check the address and try again`,
          timeout: 8000
        })
        // this.bip353Valid = false
        return false
      }
    },
    toggleAddresses: async function (wallet) {
    wallet.expanded = !wallet.expanded
    if (wallet.expanded && !wallet.addresses.length && !wallet.loadingAddresses) {
      wallet.loadingAddresses = true
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/wallet/${wallet.id}/addresses`,
          this.inkey
        )
        wallet.addresses = data.addresses || []
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      } finally {
        wallet.loadingAddresses = false
      }
    }
  },
    generateAddress: async function (wallet) {
       this.$q.notify({
        type: 'info',
        message: 'Open this wallet in the Thrilla app to generate a labeled address.',
        caption: 'LNbits doesn\'t store wallet keys for security reasons.',
        timeout: 7000,
        actions: [{
          label: 'Open Thrilla',
          color: 'white',
          handler: () => window.open(this.thrillaUrl, '_blank'),
        }],
      })
    },

    saveAddress: async function (wallet, addr) {
      const rw = this.walletAccounts.find(w => w.id === wallet.id)
      if (!rw) return
      try {
        const {data} = await LNbits.api.request('POST', `/siLNt/api/v1/wallet/${rw.id}/addresses`, this.inkey, {
          sp_address: addr.sp_address,
          label_index: addr.label_index          
        })
        const idx = rw.addresses.findIndex(a => a._tempId === addr._tempId)
        if (idx !== -1) rw.addresses.splice(idx, 1, { ...data, saved: true })
        this.$emit('addresses-changed')
        Quasar.Notify.create({ type: 'positive', message: 'Address saved.' })
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },

    deleteAddress: async function (wallet, addr) {
      const rw = this.walletAccounts.find(w => w.id === wallet.id)
      if (!rw) return
      if (!addr.id) {
        rw.addresses = rw.addresses.filter(a => a._tempId !== addr._tempId)
        return
      }
      LNbits.utils.confirmDialog('Delete this labeled address?').onOk(async () => {
        try {
          await LNbits.api.request('DELETE', `/siLNt/api/v1/wallet/${rw.id}/addresses/${addr.id}`, this.inkey)
          rw.addresses = rw.addresses.filter(a => a.id !== addr.id)
          Quasar.Notify.create({ type: 'positive', message: 'Address deleted.' })
        } catch (error) {
          LNbits.utils.notifyApiError(error)
        }
      })
    },
    created: async function () {
      if (this.inkey) {
        await this.refreshWalletAccounts()
      }      
    },    
    showQrCodeAddress: function (address) {
      this.qrDialog.address = address
      this.qrDialog.show = true
    },
    closeFormDialog: function () {
      this.formDialog.data = {               
        hr_address: '',     // ← empty string not null
        last_height: '',
        mnemonic: '',
        network: 'mainnet',     
        is_unique: false
      }
    },
    closeUpdateDialog: function () {
      this.updateDialog.data = {
        is_unique: false
      }
    },
    getAccountDescription: function (accountType) {
      return getAccountDescription(accountType)
    },
    
    showAddAccountDialog: function () {
      this.formDialog.data = {      
      hr_address: '',
      last_height: '',
      mnemonic: '',
      network: 'mainnet'
    }
      this.formDialog.show = true      
    },
    showUpdateWalletDialog: function () {
      this.updateDialog.show = true      
    },
    // todo: bad. base.js not present in custom components
    copyText: function (text, message, position) {
      var notify = this.$q.notify
      Quasar.copyToClipboard(text).then(function () {
        notify({
          message: message || 'Copied to clipboard!',
          position: position || 'bottom'
        })
      })
    },
    showQrCode: function (wallet) {
      this.qrDialog.address = wallet.sp_address || ''
      this.qrDialog.show = true
    },    
  },
  created: async function () {   
    if (this.inkey) {
      await this.refreshWalletAccounts()          
    }
  }
})
