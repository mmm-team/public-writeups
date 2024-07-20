# Penguin and Crap - Reversing
```
🐧https://www.youtube.com/watch?v=sCszdeWTzKs&t=0s
🦀https://www.youtube.com/watch?v=qElvTW-8-W8&t=0s.

https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/penguin-and-crab/penguin-and-crab-276719eb79c08d95ecaa6075e317b0641fb15d1f.tar.gz

Author: wxrdnx
25 Teams solved.
```

# Analysis
The Linux kernel module that checks the flag is given in the initramfs. cpio. The kernel module simply checks the flag entered and prints the result. 

The flag is 100 chars, and the checking algorithm calculates the input as a 32-bit integer. There are multiple checking algorithms exist, such as subset sum problem, discrete logarithm, multiplication, xor, rotate, and so on.

I've analyzed the whole flag-checking algorithm and wrote inverse operations.

For the subset-sum problem, the density is low (~0.5), so we can use a Low-Density attack. And, for the discrete logarithm problem, the modulus is prime. So we can recover exponents. Other operations are trivial to inverse.

The whole solver script is in solver.py.
