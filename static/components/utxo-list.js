window.app.component('utxo-list', {
  name: 'utxo-list',
  template: '#utxo-list',
  delimiters: ['${', '}'],

  props: [
    'utxos',
    'accounts',
    'selectable',
    'payed-amount',
    'sats-denominated',
    'mempool-endpoint',
    'filter'
  ],

  data: function () {
    return {
      utxosTable: {
        columns: [
          {
            name: 'expand',
            align: 'left',
            label: ''
          },
          {
            name: 'selected',
            align: 'left',
            label: '',
            selectable: true
          },
          {
            name: 'status',
            align: 'center',
            label: 'Status',
            field: 'utxo_state',
            sortable: true
          },
          {
            name: 'amount',
            align: 'left',
            label: 'Amount',
            field: 'amount',
            sortable: true
          },
          {
            name: 'date',
            align: 'left',
            label: 'Date',
            field: 'timestamp',
            sortable: true,
            sort: (a, b) => a - b
          },
          {
            name: 'label',
            align: 'left',
            label: 'Label',
            field: 'label',
            sortable: false
          },
        ],
        pagination: {
          rowsPerPage: 10
        }
      },
      utxoSelectionModes: [
        'Manual',
        'Random',
        'Select All',
        'Smaller Inputs First',
        'Larger Inputs First'
      ],
      utxoSelectionMode: 'Random',
      utxoSelectAmount: 0
    }
  },

  computed: {
    columns: function () {
      return this.utxosTable.columns.filter(c =>
        c.selectable ? this.selectable : true
      )
    },
    unspentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'unspent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    },
    spentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'spent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    }
  },

  methods: {
    satBtc(val, showUnit = true) {
      return satOrBtc(val, showUnit, this.satsDenominated)
    },
    // Kept for compatibility but not used for blindbit UTXOs (no wallet account)
    getWalletName: function (walletId) {
      const wallet = (this.accounts || []).find(wl => wl.id === walletId)
      return wallet ? wallet.title : 'unknown'
    },
    getTotalSelectedUtxoAmount: function () {
      const total = (this.utxos || [])
        .filter(u => u.selected)
        .reduce((t, a) => t + (a.amount || 0), 0)
      return total
    },
    refreshUtxoSelection: function (totalPayedAmount) {
      this.utxoSelectAmount = totalPayedAmount
      this.applyUtxoSelectionMode()
    },
    unspentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'unspent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    },
    spentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'spent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    },
    formatTimestamp: function (timestamp) {
      if (!timestamp) return 'N/A'
      try {
        const date = new Date(timestamp * 1000)
        const day = String(date.getDate()).padStart(2, '0')
        const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
        const month = months[date.getMonth()]
        const year = date.getFullYear()
        const hours = String(date.getHours()).padStart(2, '0')
        const mins = String(date.getMinutes()).padStart(2, '0')
        return `${day} ${month} ${year} ${hours}:${mins}`
      } catch (e) {
        return 'Unknown'
      }
    },
    updateUtxoSelection: function () {
      this.utxoSelectAmount = this.payedAmount
      this.applyUtxoSelectionMode()
    },
    startEditLabel: function (utxo) {
        utxo.editingLabel = true
        utxo.labelDraft = utxo.label || ''
      },

      cancelEditLabel: function (utxo) {
        utxo.editingLabel = false
        utxo.labelDraft = ''
      },

      saveLabel: async function (utxo) {
        try {
          await LNbits.api.request(
            'PUT',
            `/siLNt/api/v1/utxos/${utxo.txid}/label`,
            this.g.user.wallets[0].inkey,
            { label: utxo.labelDraft || '' }
          )
          utxo.label = utxo.labelDraft || ''
          utxo.editingLabel = false
          Quasar.Notify.create({
            type: 'positive',
            message: utxo.label ? `Label set: ${utxo.label}` : 'Label cleared.',
            timeout: 3000
          })
        } catch (error) {
          LNbits.utils.notifyApiError(error)
        }
      },
    applyUtxoSelectionMode: function () {
      const mode = this.utxoSelectionMode
      const isSelectAll = mode === 'Select All'
      if (isSelectAll) {
        this.utxos.forEach(u => (u.selected = true))
        return
      }

      const isManual = mode === 'Manual'
      if (isManual || !this.utxoSelectAmount) return

      this.utxos.forEach(u => (u.selected = false))

      const isSmallerFirst = mode === 'Smaller Inputs First'
      const isLargerFirst = mode === 'Larger Inputs First'
      let selectedUtxos = this.utxos.slice()
      if (isSmallerFirst || isLargerFirst) {
        const sortFn = isSmallerFirst
          ? (a, b) => a.amount - b.amount
          : (a, b) => b.amount - a.amount
        selectedUtxos.sort(sortFn)
      } else {
        // default to random order
        selectedUtxos = _.shuffle(selectedUtxos)
      }
      selectedUtxos.reduce((total, utxo) => {
        utxo.selected = total < this.utxoSelectAmount
        total += utxo.amount
        return total
      }, 0)
    }
  },  
  created: async function () {}
})