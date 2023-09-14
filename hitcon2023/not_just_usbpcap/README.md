# Not just usbpcap

We get a pcap with mostly USB traffic, along with traffic from bluetooth earbuds.

We can use https://github.com/TeamRocketIst/ctf-usb-keyboard-parser with some modifications to look at keystrokes.
```
tshark -r ./release-7ecaf64448a034214d100258675ca969d2232f54.pcapng -Y 'usbhid.data && usb.data_len == 8' -T fields -e usbhid.data | sed 's/../:&/g2' > data
```
We get the following keystrokes, which tells us the flag format:
```
Sssoorrrryy,,  nnoo  ffllaagg  hheerree..  Tttrryy  hhaarrddeerr..

Buutt  ii  ccaann  tteellll  yyoouu  tthhaatt  tthhee  ffllaagg  ffoorrmmaatt  iiss  hhiittccoonn{lloowweerr--ccaassee--eenngglliisshh--sseeppaarraatteedd--wwiitthh--ddaasshh}

Aggaaiinn,,  tthhiiss  iiss  nnoott  tthhee  ffllaagg  :(
```

Packet 1951 tells us that the codec for the audio is MPEG2 AAC LC, sampling frequency is 48000hz, 2 channels.

We can extract the data as follows:
```
tshark -r ./release-7ecaf64448a034214d100258675ca969d2232f54.pcapng -Y 'bta2dp' -T fields -e data.data > data
```
then run
```
s = open('data').read()
open('data_bin','wb').write(bytes.fromhex(s))
```
to convert to binary, then use https://github.com/dhavalbc/MPEG2-4-AAC-DECODER/tree/master with the 48khz option to get the audio, which tells us the flag.
