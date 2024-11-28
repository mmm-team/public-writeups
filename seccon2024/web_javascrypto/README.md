## javascrypto - @disna

* web
* 13 solves
* 248 points

> This is not a typo.
>
> Challenge: http://javascrypto.seccon.games:3000
>
> Admin bot: http://javascrypto.seccon.games:1337
>
> [JavaScrypto.tar.gz](JavaScrypto.tar.gz) d261a5b574a3f30862ee3500d59c3cc84cf37c25
>
> author: Satoooon

(Forewarning: the file we downloaded does not have the same `sha1sum` checksum as what is written in the challenge description)

JavaScrypto is a note application, where the goal is to steal admin's flag stored in a note. Notes are stored as a combination of an `iv` and a `ciphertext`, keyed by `UUID`, in the backend, where the client encodes their plaintext with a randomly generated key persisted in `localStorage` and a random `iv`, and decodes with that same key, `iv` and generated ciphertext. The last such note (`currentId`) is also persisted in `localStorage`.

```js
      const key = getOrCreateKey();
      
      const id = purl().param().id || localStorage.getItem('currentId');
      if (id && typeof id === 'string') {
        readNote({
          id,  
          key, 
        }).then(content => {
          if (content) {
            localStorage.setItem('currentId', id); // old flag id gets removed
            document.getElementById('note').innerHTML = content; // xss sink
          } else {
            document.getElementById('note').innerHTML = 'Failed to read';
          }
        });
      } else {
        document.getElementById('note').innerHTML = 'No note';
      }
      ...
```
_index.html_'s script contents

There is a pretty obvious XSS sink here (`innerHTML` assignment), but not only does the assignment override the current value of `currentId` (which is where admin's flag would be stored), but the contents depends on the result of decoding the `ciphertext` with `iv` and `key`, where we only control `id` and therefore `ciphertext` and `iv`, not `key`.

```js
const readNote = async ({ id, key }) => {
  const cipherParams = await fetch(`/note/${id}`).then(r => r.json());
  const { iv, ciphertext } = cipherParams;
  return decryptNote({ key, iv, ciphertext });
}
...
const decryptNote = ({ key, iv, ciphertext }) => {
  const rawKey = CryptoJS.enc.Base64.parse(key);
  const rawIv = CryptoJS.enc.Base64.parse(iv);
  const rawPlaintext = CryptoJS.AES.decrypt(ciphertext, rawKey, {
    iv: rawIv, 
  });
  return rawPlaintext.toString(CryptoJS.enc.Latin1);
}
```

But wait, what's this `purl()` thing in `index.html`? From an intuitive standpoint when solving web CTF chals, such deviations from 'normal' applications are sus and worthy of investigation.

Not only was the last commit for this package 7 years ago, but there's even a very helpful [issues entry](https://github.com/allmarkedup/purl/pull/89/files) that warns of prototype pollution in a `promote` function. A little more searching reveals it is called as part of `merge()`, called by `parseString()`, called by `parseUri()`, called by `purl()`. Excellent. This yields prototype pollution as long as we supply query parameters of the form `__proto__[propToPollute]=valueToPollute`.

The goal remains to control or influence `key`, such that we can control the output of decoding a note, to display arbitrary HTML to the admin for XSS. There is afaik no useful protopollute gadget to abuse in either `index.html` or `note.js`. So, we look to the package the client imports to encrypt/decrypt: [`crypto-js.js`](crypto-js.js). The client imports a minimized version, and it is often helpful to find the unminified version and run it locally in node to step through/test parts of this module.

The client calls `CryptoJS.enc.Base64.parse(key)`:
```js
              ...
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }
              ...
              return parseLoop(base64Str, base64StrLength, reverseMap);
```
_parse(base64Str)_

```js
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              var bitsCombined = bits1 | bits2;
	              words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
```
_parseLoop(base64Str, base64StrrLength, reverseMap)_

`reverseMap` is, at first, uninitialized, and so we can pollute it with a map of our own. It is used to translate groups of base64 characters to their bitwise representation, which is then converted to a set of bytes. By zero'ing out this map, we can force the `key` to be 32 bits of 0's. This creates a side effect that the other `parse` calls (which happens for both `iv` and `ciphertext`) will also output zeros.

Fortunately, we control `ciphertext`, and it is not restricted to the standard base64 charset (i.e., JSON supports unicode characters). So, we define a set of mappings for unicode characters to the original bitwise representations for the original base64 charset, to get a non-zero ciphertext we control. This yields arbitrary HTML, and therefore XSS:

```js
reverseMap['\u0080'] = reverseMap[String.fromCharCode('A')] // support new charset mapping
reverseMap['\u0081'] = reverseMap[String.fromCharCode('B')]
...
reverseMap[String.fromCharCode('A')] = 0 // zero out mappings for the original base64 charset
...
reverseMap[String.fromCharCode('=')] = 0
```

Now, we're faced with a little problem:
```js
localStorage.setItem('currentId', id); // old flag id gets removed
document.getElementById('note').innerHTML = content; // xss sink
```

We must find a way to somehow preserve `currentId` or otherwise read the flag before it gets nuked by us inserting new content. Before Chromium introduced partitioned caching, this could be achieved by sending admin to a site we control, opening an iframe without changing its contents (so it would display the original flag in its HTML), then creating another iframe that triggers the XSS payload, and accessing the first iframe with flag through XSS to win. Now, with partitioned caching, even if an iframe and a tab share the same origin, their localStorage contents differ. Thus, we instead trigger XSS within an iframe, open a tab using that XSS, and then we proceed to read that tab's contents to get the flag, which we then exfiltrate.

To summarize, the [exploit](solve/solve_chal.sh) flow:
1. Send admin to our server
2. Our server opens an iframe to the challenge domain, which includes the XSS payload
3. Our XSS payload opens a new window towards the challenge domain
4. Our XSS payload reads the DOM from this reference to get flag

`SECCON{I_can't_make_real_crypto_challenges}`