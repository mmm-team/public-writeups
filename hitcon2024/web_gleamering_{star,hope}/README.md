# Gleamering {Star,Hope} - Web
```
Like a star in the sky, gleamering, remembering all the things we've done.

Instancer: http://gleamering.chal.hitconctf.com/

Attachment: https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/gleamering/gleamering-8acf90164f9aed0ce5e4018b3e9ea66a203022e5.tar.gz

Author: bronson113
7 Teams solved.
```

```
At last, when all sights of light disappear, only the hope gleamering within you.

PS. This is part 2 to Gleamering Star

Instancer: http://gleamering.chal.hitconctf.com/

Attachment: https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/gleamering/gleamering-8acf90164f9aed0ce5e4018b3e9ea66a203022e5.tar.gz

Author: bronson113
4 Teams solved.
```

# Gleamering Star
The service provides register, login, add-post, encrypt-post features. The first goal is reading admin's encrypted post, and second goal is gaining arbitrary code executoin.

To read other user's encrypted post, we must know item_id which depends on `AUTHORIZATION_KEY`. Since the post encryption uses `AUTHORIZATION_KEY` too, we have to leak `AUTHORIZATION_KEY`.

While encrypting the post, the service uses ffi, and the compiled ffi library locate at gleamering_hope/priv/gleamering_hope_ffi.so.

The following is decompiled `stream_xor` function which used in encryption.

```c
__int64 __fastcall stream_xor(__int64 env, __int64 a2, _QWORD *a3)
{
  __int64 v4; // rdx
  __int64 v5; // rcx
  __int64 v6; // r8
  __int64 v7; // r9
  ErlNifBinary buf; // [rsp+20h] [rbp-D0h] BYREF
  ErlNifBinary prefix; // [rsp+50h] [rbp-A0h] BYREF
  ErlNifBinary key; // [rsp+80h] [rbp-70h] BYREF
  ErlNifBinary msg; // [rsp+B0h] [rbp-40h] BYREF
  __int64 binary; // [rsp+E0h] [rbp-10h]
  int i; // [rsp+ECh] [rbp-4h]

  if ( !enif_inspect_binary(env, *a3, &msg)
    || !enif_inspect_binary(env, a3[1], &key)
    || !enif_inspect_binary(env, a3[2], &prefix) )
  {
    return enif_make_badarg(env);
  }
  if ( msg.size )
  {
    if ( !enif_alloc_binary(msg.size + prefix.size, &buf) )
      return enif_make_badarg(env);
    memcpy(buf.data, prefix.data, prefix.size);
    for ( i = 0; i < msg.size; ++i )
      buf.data[prefix.size + i] = key.data[i] ^ msg.data[i];
    binary = enif_make_binary(env, &buf);
    if ( is_backdoor(env, (__int64)&buf, v4, v5, v6, v7, buf.size, buf.data) )
      hex_decode(&buf, msg.data, msg.size);
    return binary;
  }
  else
  {
    if ( !enif_alloc_binary(8LL, &buf) )
      return enif_make_badarg(env);
    *(_QWORD *)buf.data = &enif_alloc_binary;
    return enif_make_binary(env, &buf);
  }
}
```

While encrypting the message via xor, there is no mod to key index (`buf.data[prefix.size + i] = key.data[i] ^ msg.data[i];`). This can lead memory leak.

So, we can dump large amount of bytes through memory leak and finding `AUTHORIZATION_KEY` was able.

The full exploit script is in `gleamering-star-solver.py`.

# Gleamering Hope
If the `is_backdoor` function return true, the `hex_decode` function is called. But, since the dst buffer is `&buf` not `buf.data`, the stack buffer overflow is occured.

Further, if the `msg.size` is 0, the library simply returns binary address (`&enif_alloc_binary`).

We have a stack overflow, no canary, binary base address. So gaining shell through ROP is trivial.

We used `execv` function to execute system command, and got flag via curl command.

the full exploit script is in `gleamering-hope-solver.py`.
