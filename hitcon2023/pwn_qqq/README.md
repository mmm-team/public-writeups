# Pwn - qqq

## Overview

This challenge is a pwnable challenge based on Qt on Windows.
Three files were given: the challenge (exe file), kernel32.dll and ntdll.dll.

There are two types of objects: "script" and "testcase"; script is a named JavaScript snippet that is ran by QJSEngine,
and "testcase" is connected to a script with additional parameters like timeout.

Users can create a script, testcase and run a testcase to get how long it took.
To collect timeout, the program runs the following script around our script.

```js
// Timer is a Qt-native script bound to a C++ object named QQTimer.
var x = Timer.elapsed()

// our script here

// Set jsTime field of QQTimer object using a C++ method; this is connected via Qt metacall system
Timer.setJsTime(x - Timer.elapsed())
```

## Bug

The bug is that the timer (QQTimer) is only created once, and bound to the QJSEngine without increasing reference count.
The js engine is bound to each testcase, so if a testcase is deleted, the global QQTimer object is also destroyed, while other testcase can point to the timer.
This leads to use-after-free.

Also, the testcase, QQTestcase has the same heap size, so the attacker can make it a type confusion primitive since the freelist is shared between them.
There is an useful field at offset 0x10: timeout (QQTimer) and timer (QQThread). Since timeout is at timer->timeout and user can get/set them, we can convert
UAF into arbitrary read/write primitive. Using this primitive, we could leak the address of dlls (ntdll, kernel32) and modify `__vftable` pointer of QQTimer/QQTestcase.

Since the program is inside AppJailLauncher, we chose to run a shellcode that reads flag.txt instead of executing process. To acheive this,
we used a gadget that sets stack pointer and PC, inside `longjmp` of ntdll. Using this, we could do ROP to call VirtualProtect and jump to the shellcode.

## Exploit

See [qqq.py](./qqq.py).