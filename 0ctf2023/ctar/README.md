# ctar&emsp;<sub><sup>Misc, 305 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

For each connection, the server creates a new temporary directory and allows the user to take the following operations:
1. Add a new file with a random name and content of the user's choice (and tell the user the name of the file), and add the path of the file to an in-memory map with a value of 1
2. Upload a ctar file, mark all files in the ctar file in the mapping with a value of 1, and unpack the ctar file into the directory
3. Construct a tar file containing all files in the mapping, then encrypt it to get a ctar file and send it to the user
4. Add a new file with a random name and the contents of the flag (and tell the user the name of the file), and add the path of the file to the mapping with a value of 0

A "ctar file" is a tar file encrypted via ChaCha20 with a secret key and a random nonce.  The nonce is appears as the first 8 bytes of the file, and the encrypted file follows.

The upload operation also has a couple of quirks:
- When uploading a ctar file, if the decrypted content does not appear to be a valid tar file, the server will return the decrypted content to the user.
- All files in the ctar file are marked in the mapping with a value of 1 before any files are unpacked.
- Due to a try-except around the entire process, if unpacking the ctar file fails, the server will continue with the main loop.

This leads to the following basic outline for an attack to retrieve the flag:
1. Add the flag file to the directory
2. Upload a ctar file containing a file with the same name as the flag file, which is a valid tar file but which fails to unpack (thus leaving the flag file behind but clearing the flag in the mapping)
3. Download the ctar file
4. Reupload the ctar file with some bytes corrupted in a known way (thus causing the server to return the decrypted content, which should provide enough information to recover the flag)

Step 2 requires two key components: a crafted tar (or sequence of tars) that will fail to unpack, and the ability make the server accept an the crafted tar as a ctar file.

In order to turn an arbitary tar into a ctar, we send the server a large number of null bytes and read its response.  It will attempt to interpret this as a ctar file, and when it inevitably fails, it will return the decrypted content.  Since the ChaCha20 stream cipher is just XORing a keystream with the plaintext, the decrypted content is equal to the keystream with a nonce of eight null bytes; we can simply XOR this with any tar file we want to get a valid ctar file.

With this ability, we now just need a tar file that will fail to unpack.  The simplest way to do that is to try to unpack a file at a subpath of the flag file; however, this will cause problems when we try to download the ctar file later, since the server will then be expecting to include that file in the ctar download, and will fail when it can't find it.

The approach we came up with is to create a symlink and then try to extract at a subpath of that symlink; so for example, we could have a tar (call it `tar1`) that contains the following files:
- `sym`: symlink to `y`
- `sym/bar`: file with contents `hi`
- File with the same name as the flag: file with contents `hi`

If we try to extract everything from this tar, it will fail at the `y/bar` step because it will refuse to unpack at a subpath of a symlink.  We can then upload a second tar (`tar2`) that rewrites the symlink and makes it resolve properly, specifically with contents like:
- `sym`: symlink to `foo`
- `foo/bar`: file with contents `hi`

Now all files resolve properly: `sym` is still a symlink that exists, and `sym/bar` and `foo/bar` are the same file.

Putting it all together, we can carry out the full attack:
1. Add the flag file to the directory
2. Upload a large number of null bytes; call the output from the server error `keystream`
3. Upload `b"\x00" * 8 + (tar1 XOR keystream)`, which clears the flag in the mapping, leaves the actual flag behind, but leaves our directory in a bad state
4. Upload `b"\x00" * 8 + (tar2 XOR keystream)`, which fixes the directory
5. Download the ctar file, which contains the flag file (call this `flag_ctar`)
6. Upload `flag_ctar XOR (b"\xcc" * len(flag_ctar))`; call the output from the server error `flag_tar_cc`
7. XOR `flag_tar_cc` with `b"\xcc" * len(flag_tar_cc)` to get `flag_tar`
8. Extract `flag_tar` to get the flag

The full exploit script is in [solve.py](./solve.py).
