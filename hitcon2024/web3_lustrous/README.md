# Lustrous - Web3

## Description

- Bug 1: https://github.com/vyperlang/vyper/security/advisories/GHSA-gp3w-2v2m-p686
    - We can make we always draw the game against the bot.
    - Allows resetting to stage 1 without any ETH loss.
- Bug 2: https://github.com/vyperlang/vyper/security/advisories/GHSA-2q8v-3gqq-4f8p
    - During concat function, it overwrites the most significant bit/byte (MSB) of the callee's memory.
    - We can exploit this by overwriting the MSB of the health value. If the health value is a signed negative integer, this can turn it into an extremely large number.

## Flag

- `hitcon{f1y_m3_t0_th3_m00n_3a080ea144010d74}`