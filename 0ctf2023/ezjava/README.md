# ezjava

* Writeup by Ricky, Ryan, Vie, Alueft

## Summary
`aviatorscript` (JVM-hosted language) jail that you upload into an `ipfs` node and use the app's `curl` to navigate to for RCE.

## Overview

Sourceless web-app that has an endpoint called `/aviatorscript` and a homepage which tells you to input any URL and the app's curl-as-a-service (CaaS) will visit it. There exists a restrictive allowlist that you must blackbox to figure out what it looks like. 

The homepage has a placeholder URL `/eval` to a localhost endpoint which just hosts a simple addition equation in plaintext. If you submit it, `/aviatorscript` will ostensibly evaluate that equation and print it. 

## Solution
Googling around for `aviatorscript` gives you [this](https://github.com/killme2008/aviatorscript/blob/master/README-EN.md), describing it as a JVM-hosted scripting language. More documentation about it is found [here](https://www.yuque.com/boyan-avfmj/aviatorscript/cpow90). It can be hypothesized that the `/aviatorscript` endpoint will attempt to evaluate the results of where it curls to, as shown with the placeholder `/eval` URL. 

After some time blackboxing the CaaS, one can observe that the `ipfs://` protocol is allowed. Some [documentation and research](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions) into this protocol shows us that we can host files in an IPFS node, which we use to our advantage to bypass the CaaS allowlist. 

The question then navigates to formulating an appropriate `aviatorscript` jail now that we can send the CaaS to arbitrary IPFS locations. Certain ideas like Java class deserialization attacks or plain ol' evals don't do the trick - there appears to be another restrictive allowlist that dictates what expressions are allowed to be evaluated. After some additional blackboxing we discover that primitives such as `seq.list()` and `getClass()` are allowed. We use these, alongside a few other native functions (such as `invoke()`, `getMethods()` and `toArray()`), to call `java.lang.Runtime` and read us the flag. Our full payload is below - we base64 encode it to a tmp file to avoid weird parsing issues with in-line bash commands. 

```java
invoke(getMethods(invoke(getMethods(getClass(getClass("")))[3], nil, toArray(seq.list("java.lang.Runtime"))))[12],
  invoke(getMethods(invoke(getMethods(getClass(getClass("")))[3], nil, toArray(seq.list("java.lang.Runtime"))))[0], nil, toArray(seq.list())),
  toArray(seq.list("bash -c echo${IFS}BASE64_COMMAND_HERE>/tmp/n;base64${IFS}-d${IFS}/tmp/n|bash"))
)
```

The TL;DR is as follows:

1. Construct your aviatorscript jail to read the flag.
2. Upload your aviatorscript code into the ipfs node network.
3. Tell the CaaS in the app to navigate to `ipfs://<YOUR_UPLOADED_FILE>`
4. Okay flag