---
layout: post  
title: "Challenge cocorico, FCSC 2025"
date: 2025-04-28 23:41:40 +0100
categories: CTF
---

Petit challenge crypto disponible ici :
[https://hackropole.fr/fr/challenges/crypto/fcsc2025-crypto-cocorico/](https://hackropole.fr/fr/challenges/crypto/fcsc2025-crypto-cocorico/)

Mauvaise implementation de l'AES en mode OFB avec un IV fixe et une clef fixe. Le chiffrement revient donc à faire un XOR. La clef ne change qu'à chaque lancement du programme qui autorise à se relogger.
1 On a le texte en clair (nouvel utilisateur) et le texte "chiffré" (token).
2 On peut en déduire la valeur à passer à XOR pour passer de l'un à l'autre.
3 On connait aussi ce qui est attendu : json(toto,admin). On xor cette chaine (+le crc) pour avoir le token.

```bash
➜  cocorico ./exploit.py
[+] Opening connection to chall.fcsc.fr on port 2150: Done
cleartext   : {"name": "mdrg", "admin": false}
legit token : 19f88aef03b4db929e85459857345362160fb051f442f51d8ecd8d5cb0f5a8d7b42745c0
keystream   : 62dae48e6ed1f9a8bea728fc2553714e362dd135992b9b3fb4edeb3ddc86cdaa7bb746de
adminuser   : {"name": "toto",  "admin": true}
admintoken  : 19f88aef03b4db929e855c93513c5362160df354fd46f25196d7cb49aef3a8d7b61470d6
[*] Switching to interactive mode
Congrats! Here is your flag:
FCSC{56e8ee27c9039b13a2b896da9a95a266cadd9a6e06e6d1f140f3df6cbed6332c}
```

```python 
#!/usr/bin/env python3

from pwn import *
import re
from zlib import crc32

# Fonction XOR entre deux chaînes de bytes
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
    
#context.log_level = 'DEBUG'
context.arch='amd64'

local=False

if local:
    p=process(['python3','cocorico.py'])
else:
    p=remote('chall.fcsc.fr',2150)

p.sendlineafter(b'>>> ',b'1')
p.sendlineafter(b'(y/n) ',b'y')
p.sendlineafter(b'Name: ',b'mdrg')
token=p.recvuntil(b'>>> ')
token=re.search(r"([a-z0-9]{72})",token.decode())
token=token[0]
cleartext=b'{"name": "mdrg", "admin": false}'
print('cleartext   : '+cleartext.decode())
print('legit token : '+token)
keystream=xor_bytes(unhex(token),cleartext+int.to_bytes(crc32(cleartext), 4, byteorder='big'))
print('keystream   : '+keystream.hex())

adminuser=b'{"name": "toto",  "admin": true}'
print('adminuser   : '+adminuser.decode())
admintoken=xor_bytes(adminuser+int.to_bytes(crc32(adminuser), 4, byteorder='big'),keystream)
print('admintoken  : '+admintoken.hex())

p.sendline(b"1")
p.sendlineafter(b'(y/n) ',b'n')
p.sendlineafter(b'Token: ',admintoken.hex().encode())
p.interactive()
```