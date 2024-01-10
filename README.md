
# trtc-usersig-worker
trtc usersig service run on cloudflare workers


[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Tencent-RTC/trtc-usersig-workers)


- Config your sdkappid and secret in wrangler.toml

```
[vars]
SDKAPPID = 14xxxxxxxx
SECRET = "xxxxxxxxxx"

```


- Local Dev

```
npm install
npm run dev
```


- Deploy to cloudflare workers
```
npm run deploy
```
