# Trillion Bank&emsp;<sub><sup>Web, 108 points</sup></sub>

_Writeup by [@bluepichu](https://github.com/bluepichu)_

The server implements a simple money transfer API.  New accounts are given $10 to start, and you can get the flag if you can get an account to have at least $1,000,000,000,000.

My first thought was a race condition on transfers, allowing a transfer from A to B and B to A simultaneously, resulting in funds being duplicated.  However, the transfer endpoint properly locks the source user before transferring funds, so all this accomplishes is a deadlock.

The next thing I noticed is that the transfer endpoint identifies recipient users by their username rather than by ID, and the database schema does not have a uniqueness constraint on users.  However, the server maintains its own in-memory list of usernames, so creating two users with the same username should not be possible.  This gives rise to two plans of attack:

1. Create a user with a known username, then crash the server to clear its in-memory list of usernames, and then create a second user with that username.
2. Create two users with different usernames that the database normalizes to the same value.

Option 2 turned out to be the way to go, since MySQL will silently truncate text fields to 65535 characters if they are too long.  In contrast, the in-memory list of usernames can store usernames of any length.

The full attack is:

1. Create three users that we'll call A, B, and C.  A's username can be anything, but B and C must both lave length greater than 65535 characters start with a common 65535-character prefix.
2. Repeatedly do the following:
	a. Transfer all funds in account A to the common 65535-character prefix of B and C.  This will cause the funds to be sent to both B and C.
	b. Transfer all funds in accounts B and C to account A.  The net result is that double the funds will be in A than were there when we started.
3. Repeat step 2 until account A has at least $1,000,000,000,000, and retrieve the flag: `SECCON{The_Greedi3st_Hackers_in_th3_W0r1d:1,000,000,000,000}`.

My solution script can be found in [solve.mjs](./solve.mjs).
