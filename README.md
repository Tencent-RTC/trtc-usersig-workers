
# trtc-usersig-workers
trtc usersig service run on cloudflare workers




### Local Dev  


1、Config your sdkappid and secret in wrangler.toml


```yaml
[vars]
SDKAPPID = 14xxxxxxxx
SECRET = "xxxxxxxxxx"

```


2、Start local server  
```shell
npm install
npm run dev
```



### Deploy to cloudflare workers



1、Config your sdkappid and secret in wrangler.toml


```yaml
[vars]
SDKAPPID = 14xxxxxxxx
SECRET = "xxxxxxxxxx"

```

2、You need to have a cloudflare account


3、Deploy

```shell
npm run deploy
```

You should get some workers url like  `https://trtc-usersig-workers.xxxxxxx.workers.dev`

