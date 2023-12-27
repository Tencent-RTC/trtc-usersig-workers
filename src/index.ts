import { Hono } from 'hono'
import { serveStatic } from 'hono/cloudflare-workers'


const TLSSigAPIv2 = require("tls-sig-api-v2");


type Bindings = {
    MY_BUCKET: R2Bucket
    USERNAME: string
    PASSWORD: string
  }

const app = new Hono<{ Bindings: Bindings }>()


app.get('/', (c) => c.text('Hello!'))


app.post('/config', async (c) => {

    const sig = new TLSSigAPIv2.Api(c.env.USERNAME, c.env.USERNAME);
    const body = await c.req.json()
    const userid = body.userid
    
    const userSig = sig.genSig(userid, 3600 * 24);

    c.json({
        userSig: userSig,
        sdkappid: c.env.USERNAME,
    })
    return 
})



app.get('/static/*', serveStatic({ root: './' }))

export default app
