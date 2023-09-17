from pwn import *

alpha = '1234567890QWERTYUIOPASDFGHJKL{ZXCVBNM_-}'

x = [21,12,32,32,18,35,29,26,11,34,25,38,4,7,12,28,38,10,11,13,28,38,32,28,21,11,38,16,23,13,17,38,
31,16,15,2,38, # 00036
15,25,27,27,38, # 00041
27,23,34,33,39 # 00046
] 

for i in x:
    print(alpha[i], end='')
print()

'''
open in BDedit
go to each entry in CLIPINF, double click the "und" program, browse menu buttons until you see the odd one out
'''
