import { Hono } from 'hono'

import { serveStatic } from 'hono/cloudflare-workers'

import Sig from './usersig'



type Bindings = {
    SDKAPPID: number
    SECRET: string
}

const app = new Hono<{ Bindings: Bindings}>()


app.post('/config', async (c) => {
    console.log(c.req)

    const body = await c.req.json()
    const userid = body.userid || 'test'
    const expire = body.expire || 86400

    const userSig = new Sig.Api(c.env.SDKAPPID, c.env.SECRET)
    
    const sig = userSig.genUserSig(userid, Number(expire))

    return c.json({
        sdkappid: c.env.SDKAPPID,
        userSig: sig,
    })
})


app.get('/pusher', serveStatic({ path: './pusher.html'}))

app.get('/player', serveStatic({ path: './player.html'}))


app.get('/', serveStatic({ path: './index.html'}))

app.get('/test', (c) => c.text('Hello Hono!'))

export default app
