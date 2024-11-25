## reiwa_rot13 - @hiswui

reiwa_rot13 was a warmup Crypto challenge solved by 127 teams, worth 91 points.

Description:

> Reiwa is latest era name in Japanese(from 2019). it's latest rot13 challenge!
> 
> note: Please submit the flag as it is.
> 
> reiwa_rot13.tar.gz 82ae08544ca583a45515b709c8d38817748d87b2


> author: kurenaif


### Challenge Overview
```py
from Crypto.Util.number import *
import codecs
import string
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 137

key = ''.join(random.sample(string.ascii_lowercase, 10))
rot13_key = codecs.encode(key, 'rot13')

key = key.encode()
rot13_key = rot13_key.encode()

print("n =", n)
print("e =", e)
print("c1 =", pow(bytes_to_long(key), e, n))
print("c2 =", pow(bytes_to_long(rot13_key), e, n))

key = hashlib.sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
print("encyprted_flag = ", cipher.encrypt(flag))
```

The challenge was fairly straightforward. It's a RSA type challenge where you're given 2 encrypted messages. The underlying plaintext is related through a simple [ROT13](https://en.wikipedia.org/wiki/ROT13) mapping.

### Solution Approach

The key setup for the private (p, q) and public keys (N, e) has no glaring vulnerabilities (with the exception of the low public exponent).

The real vulnerabilities lie in:
- the short length of the messages (10 lowercase ASCII characters)
- A linear relationship between both encrypted plaintexts

The second vulnerability allows us to leverage a [Franklin-Reiter attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack) to extract the messages. 

### Perfect! How do we do that?

The Franklin-Reiter attack relies on having a fixed relationship between both the plaintexts. For example, if we label `m_1 = X`, then `m_2 = X + R` where `R` is a fixed integer in ZMod(N).

This is great. However, there's still an important hurdle to overcome: how do you represent ROT13 mathematically? 

To do this, let's construct this step by step. Let's take a small example `ROT13('a') == 'n'`. Mathematically, we can describe this as `chr(ord('a') + 13) == 'n'`. 
In the case where we need to wrap around such as `ROT13('x') == 'k'`, we can interpret it as subtracting 13 instead like this: `chr(ord('x') - 13) == 'k'`. 

Let's extend this to multiple characters. take `ROT13('by') == 'ol'`. We can no longer use chr and ord, instead we can use long_to_bytes and bytes_to_long. We can add/subtract 13 to each character by treating our number using base256.
So, it would look like `long_to_bytes(bytes_to_long(b'by') + 13*pow(256,1) - 13*pow(256,0))  ==  b'ol'`.

Woohoo! we can now represent ROT13 mathematically. However, we have a new problem: we're not sure whether we add or subtract 13 at each of the 10 characters. 

The answer to this is admittedly a little boring: There are only about 2^10 = 1024 permuations. So, we can just brute force it :D

### Solve script
The solve script basically runs Franklin-Reiter against each of the possible ROT13 increments and finds the key that matches the prerequisite conditions. 

```py
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233
encyprted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

load('FranklinReiter.sage')

# lets NixOS work with site packages in Sage LOL 
# import sys; sys.path.append('/nix/store/qfzk5jbq9znpmyfsj8wf9drrb86w33k3-python3-3.12.7-env/lib/python3.12/site-packages')

from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib

def get_rot13_increment(guesses):
    rot13_increment = 0
    for i in range(0, 10):
        rot13_increment += pow(-1, guesses[i]) * 13 * pow(256, i)
    return rot13_increment

convert_to_bitarr = lambda x: [int(bit) for bit in bin(x)[2:].zfill(10)]

for i in range(1024):
    rot13_inc = get_rot13_increment(convert_to_bitarr(i))
    key = franklinReiter(n, e, rot13_inc, c1, c2)
    if pow(key, e, n) == c1:
       print("KEY FOUND")
       print(key)
       break
                                                                                                
key = long_to_bytes(key)
key = hashlib.sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
print("flag = ", cipher.decrypt(encyprted_flag))
```

S/O to [ValarDragon's script to run FranklinReiter](https://github.com/ValarDragon/CTF-Crypto/blob/master/RSA/FranklinReiter.sage). The prerequisite check was very loose in this solve script. I just got lucky with my values working. If you were to replicate this in the future, I would check that both m1 and m2 are encrypted as expected. 




### Final Thoughts
The challenge was quite fun. It was quite fun to figure out how to map to ROT13 mathematically (shoutout @nneonneo for explaining how ROT13 could be interpreted this way). 

Lastly, I'm not sure if the name of the challenge is a wordplay on Reiter. I interpreted it (retrospectively) as REIwa_rot13.

Once we run the solve script, we get our flag!
`SECCON{Vim_has_a_command_to_do_rot13._g?_is_possible_to_do_so!!}`
