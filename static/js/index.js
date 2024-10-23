const mapObject = obj => {
  // obj.date = Quasar.date.formatDate(new Date(obj.time), 'YYYY-MM-DD HH:mm')
  // here you can do something with the mapped data
  return obj
}

window.app = Vue.createApp({
  el: '#vue',
  mixins: [windowMixin],
  // Declare models/variables
  data() {
    return {
      protocol: window.location.protocol,
      location: '//' + window.location.hostname,
      thingDialog: {
        show: false,
        data: {}
      },
      someBool: true,
      splitterModel: 20,
      exampleData: [],
      tab: 'frameworks',
      framworktab: 'fastapi',
      usefultab: 'magicalg',
      vettedData: ''
    }
  },
  // Where functions live
  methods: {
    exampleFunction(data) {
      LNbits.api
        .request(
          'GET', // Type of request
          '/example/api/v1/test/00000000', // URL of the endpoint
          this.g.user.wallets[0].inkey, // Often endpoints require a key
          data
        )
        .then(response => {
          this.exampleData = response.data.map(mapObject) // Often whats returned is mapped onto some model
        })
        // Error will be passed to the frontend
        .catch(LNbits.utils.notifyApiError)
    },
    getVettedReadme() {
      // This is a function that gets the vetted readme from the LNbits repo and converts it from makrdown to html.
      LNbits.api
        .request('GET', '/example/api/v1/vetted', this.g.user.wallets[0].inkey)
        .then(response => {
          this.vettedData = LNbits.utils.convertMarkdown(response.data)
        })
        .catch(LNbits.utils.notifyApiError)
    },
    async initWs() {
      if (location.protocol !== 'http:') {
        localUrl =
          'wss://' +
          document.domain +
          ':' +
          location.port +
          '/api/v1/ws/32872r23g29'
      } else {
        localUrl =
          'ws://' +
          document.domain +
          ':' +
          location.port +
          '/api/v1/ws/32872r23g29'
      }
      this.ws = new WebSocket(localUrl)
      this.ws.addEventListener('message', async ({data}) => {
        const res = data.toString()
        document.getElementById('text-to-change').innerHTML = res
      })
    },
    sendThingDialog() {
      console.log(this.thingDialog)
    }
  },
  // To run on startup
  created() {
    this.exampleFunction('lorum')
    this.initWs()
    this.getVettedReadme()
  }
})
