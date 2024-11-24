## 1linepyjail - Jail Problem - @despawningbone, @lydxn, @nneonneo

1linepyjail was a jail challenge solved by 15 teams, worth 233 points.

Description:

> 1 line :)
> 
> nc 1linepyjail.seccon.games 5000
> 
> 1linepyjail.tar.gz e87d9385b0061daf9684fec758766138b5d5dad2

We're given the following Python jail script:

`print(eval(code, {"__builtins__": None}, {}) if len(code := input("jail> ")) <= 100 and __import__("re").fullmatch(r'([^()]|\(\))*', code) else ":(")`

It runs using the python:3.12.7 Docker container. The jail evaluates a Python expression of at most 100 characters, and bans non-empty parentheses. It also runs with all the builtins deleted.

## Solution

We can call zero-argument functions and perform arbitrary attribute access, which is enough to get the `object` type and its `__subclasses__()`.

One of the very useful subclasses is `_sitebuiltins.Helper`, which can be called with no arguments to launch the Python `help` system.

Typing in the name of *any* module into the help prompt will load the corresponding module and show its documentation. Afterwards, any classes loaded from that module will appear in `object.__subclasses__()`.

Therefore, we can load the `code` module via the help function, then load `code.InteractiveConsole` by traversing the class hierarchy and call its zero-argument `interact` method to obtain an unrestricted REPL.

The final payload weighs in at 96 bytes:

`[a:=().__class__.__base__.__subclasses__][0]()[158]()(),a()[-3].__subclasses__()[0]().interact()`

To use the exploit, you have to type `code` to load the code module, then `quit` to exit the help system. Then you just enter `import os` and `os.system("/bin/sh")` at the REPL to win.

Flag: `SECCON{jailctf_was_4_cr3ative_and_3njoyab1e_c7f}`
