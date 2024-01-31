# Let's party in the house

> Score: 378
>
> Pwn, Panasonic (PCSL), difficulty:Schrödinger
>
> Oh, no, in the middle of our party, there was a strange baby cry coming from the IP Camera.
> There is only one service in the device, can you figure out the baby crying? flag path: /flag
>
> nc 47.88.48.133 7777
>
> [attachment](https://rwctf.oss-accelerate.aliyuncs.com/Lets-party-in-the-house_2cd37ebed31d41afb6bbe094659985d9.tar.gz)

[NOTE: gunzip'd+xz'd version of the attachment is [here](./Lets-party-in-the-house_2cd37ebed31d41afb6bbe094659985d9.tar.xz)]

## Exploit

TL;DR: [./exp.py](./exp.py)

### Overview

The challenge is running a `BC500` firmware in qemu. The firmware sets up a web server that serves a web portal for configuring the device. While default `admin:admin` credentials work locally, they don't work on remote. Thus the goal of the challenge is to pwn the webserver to read `/flag` as an unauthenticated user.


### Reversing

On initial analysis of the rootfs file, we notice the timestamp in `build_datetime` is set to `20231023_082941`. Looking online for the firmware, we find that [`1.0.6-0294`](https://archive.synology.com/download/Firmware/Camera/BC500/1.0.6-0294) matches the specified date, and so we started looking for any public reports that were patched in next release (`1.0.7-0298`). While doing so, we find an official advisory on [Synology-SA-23:15](https://www.synology.com/en-us/security/advisory/Synology_SA_23_15) mention about a bug being used in Pwn2Own to gain arbitrary code execution. Doing more recon we found the following blog from [`TeamT5`](https://teamt5.org/en/posts/teamt5-pwn2own-contest-experience-sharing-and-vulnerability-demonstration) that talks about the bug, which we verified was also present in the shared object file from the attachment. However, we didn't find any other POC or exploit, so we decided to start reversing the files to find a way to invoke the vulnerable function with controlled inputs.

#### Setup and webd

On startup, BC500 sets up and runs a `/bin/webd` process (a slightly modified [civetweb](https://github.com/civetweb/civetweb) webserver) that serves the webpages from `/www`. By default, most of the endpoints require some form of authentication.

`webd` registers 1 request handler and 2 websocket handler. The websocket handler did an early return if `Custom.Activated`. However for the `syno-api` request handler, we found that it allows handling some requests even if `Custom.Activated` was not set. For example, the following URIs are allowed even if `Custom.Activated` is not set.

```
/
/index.html
/crypto.min.js
/vue.bundle.js
/style/main.css
/syno-api/security/info/language
/syno-api/security/info/mac
/syno-api/security/info/serial_number
/syno-api/activate
/syno-api/session
```

and

```
/syno-api/security/info
/syno-api/security/info/name
/syno-api/security/info/model
/syno-api/security/info/serial_number
/syno-api/security/info/mac
/syno-api/security/info/language
/syno-api/maintenance/firmware/version
/syno-api/security/network/dhcp
```

Taking the first set, we trace the patch in `syno-api` request handler and find that it runs the `/www/camera-cgi/synocam-param.cgi` binary, forwarding our content and other header information.

#### Reversing `synocam-param.cgi`

`synocam-param.cgi` initially reads the necessary environment variable and saves them in memory (stack or heap). Then based on the request_method, it will call the handler for supported HTTP request types: `GET`, `PUT`, `POST` and `DELETE`. While reversing the request method handlers, we noticed that if the `CONTENT_TYPE` is set to `application/json` in the HTTP request, it would first call `json_loads` on the user-provided content (saved on the heap).

Now that we know how to make the server parse user-provided JSON data, we can look into the `libjannson` bug again to understand how to exploit it.


### Exploitation

Provided `libjannson.so.4.7.0` is a modified version of [jansson](https://github.com/akheron/jansson). Most of the code we compared was similar, except for a difference in `parse_object` where the `key` is processed through `sscanf(key, "%s %s", stkbuf1, stkbuf2)` to split it on a `space`. However, this results in a bug as the `key` length can be arbitrarily long while the destination buffer is fixed size on the stack, resulting in a stack overflow.

Looking at the relevant objects used during JSON parsing, we find a few interesting properties of the `lex_t` struct:
1. `lex_t` struct is on the stack in the `json_loads` stack frame.
2. first member of the `lex_t` struct is a `stream_t` which has a function pointer (`get`) and the argument to pass to it (`data`) as the first two members.
3. Immediately after stack overflow, there is a call to `lex_scan` which calls the function pointer.

An important thing to note is that since the `sscanf` format string is `"%s %s"` and both destination buffers are on the stack, this gives us two overflows on the stack with the ability to append NULL byte. This is helpful since `libjansson` requires the input JSON data to be a valid utf-8 c-string, while our function pointer requires the top byte to be 0 (as the binary gets loaded around `0x004?0000`). Another thing we learned during debugging was that the heap starts immediately after the main binary. Thus we don't have to bruteforce heap address separately.

This gives us a pretty straightforward exploitation path:
1. Generate two strings such that the first one will overwrite the argument value in `lex_t` to the system command that we want to run (we pass this with our content that is stored on the heap). The second string will then overwrite the function pointer. For both cases, `sscanf` will append the `NULL` byte and make the address valid.
2. Merge both the strings to form a key and construct a JSON object (the value of the key doesn't matter).
3. Append a NULL byte so `libjansson` reads a shorter JSON object while we append more content to the payload
4. Add padding of `/` to the payload JSON, followed by the system command to run (we do `/bin/cp /flag /www/index.html`). Padding is required because of the UTF-8 requirement (in the function pointer address)  and thus we want to ensure all bytes of our address are within `0x23` and `0x7f`.

This results in a payload that looks something like the following:
```
{"[pad_of_length_0xa8] + [lower_3_bytes_of_address_to_cmd_to_run] + <space> + [pad_of_length_0x84] + [lower_3_bytes_of_target_address_to_run]": "val"} + "\x00" + [pad_with_char_/] + [system_cmd_to_run] + "\x00\x01"
```

NOTE: Trailing bytes are added to make things work based on experimentation.

We used the target function pointer as the following call to `popen` and then wrote a wrapper to bruteforce the aslr bits for the binary base (since aslr was enabled and binary was PIE).

```
.text:00014D5C                 MOV             R2, R0
.text:00014D60                 LDR             R3, =(aR_0 - 0x14D6C) ; "r"
.text:00014D64                 ADD             R3, PC, R3 ; "r"
.text:00014D68                 MOV             R1, R3  ; modes
.text:00014D6C                 MOV             R0, R2  ; command
.text:00014D70                 BL              popen
```

Executing the above payload will result in overwriting the `index.html` with the flag, and can then be retrieved by visiting the webpage.

**Flag:** `rwctf{d0e03372-b885-4418-9de7-145a4e66ec0d}`

#### Reversing attempt that I tried but gave up:
I tried reverse engineering the firmware file format to extract rootfs and diff `1.0.6-0294` (target version) with `1.0.7-0298` (next release). However, I was doing it without any help from the fw upgrade file in the attachment (because I was interested in knowing how to extract rootfs if I only had a firmware file), but that was slow and it did not take me anywhere. I would be interested to know if anyone has suggestions on this.
