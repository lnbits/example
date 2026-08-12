window.app.component('wallet-config', {
  name: 'wallet-config',
  template: '#wallet-config',
  delimiters: ['${', '}'],

  props: ['total', 'config-data', 'adminkey', 'inkey', 'canEditConfig'],
  emits: ['update:config-data'],
  data: function () {
    return {
      networkOptions: ['mainnet', 'testnet'],
      internalConfig: {},
      show: false
    }
  },

  computed: {
    config: {
      get() {
        return this.internalConfig
      },
      set(value) {
        value.isLoaded = true        
        value.blindbit_url = value.blindbit_url || ''
        value.mempool_url = value.mempool_url || 'https://mempool.space'       
        this.internalConfig = JSON.parse(JSON.stringify(value))
        this.$emit(
          'update:config-data',
          JSON.parse(JSON.stringify(this.internalConfig))
        )
      }
    }
  },

  methods: {    
    updateConfig: async function () {
      if (!this.canEditConfig) return
      try {
        const {data} = await LNbits.api.request(
          'PUT',
          '/siLNt/api/v1/backend/config',
          this.adminkey,
          this.config
        )
        this.show = false
        this.config = {
        ...this.internalConfig,  
        ...data,                 
        mempool_url: data.mempool_url || this.internalConfig.mempool_url || 'https://mempool.space'
      }
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },
    getConfig: async function () {
      try {        
          const [{data: blindbit}, {data: appConfig}] = await Promise.all([
          LNbits.api.request('GET', '/siLNt/api/v1/backend/config', this.inkey),
          LNbits.api.request('GET', '/siLNt/api/v1/config', this.inkey)
      ])      
        this.config =  {
      ...blindbit,
      ...appConfig,
      mempool_url: blindbit.mempool_url || 'https://mempool.space'      
    }       
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    }
  },
  created: async function () {
    await this.getConfig()
  }
})