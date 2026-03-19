# Random

## Description

Daddy, teach me how to use random value in programming!

ssh <random@pwnable.kr> -p2222 (pw:guest)

## Write-up

flag: m0mmy_I_can_predict_rand0m_v4lue!

### Contexte

Le programme semble assez simple. Il génère un nombre aléatoire
puis compare le input de l'utilisateur au nombre aléatoire généré sur
lequel il fait un XOR.

### Analyse du code

```c
#include <stdio.h>

int main(){
 unsigned int random;
 random = rand(); // random value!

 unsigned int key=0;
 scanf("%d", &key);

 if( (key ^ random) == 0xcafebabe ){
  printf("Good!\n");
  setregid(getegid(), getegid());
  system("/bin/cat flag");
  return 0;
 }

 printf("Wrong, maybe you should try 2^32 cases.\n");
 return 0;
}
```

Ce qu'on peut voir ici c'est que le nombre random est généré avec `rand()`
et non pas avec `srand()`. La seed pour la génération du random est 0 par
défaut donc `random` a toujours la même valeur à chaque execution.

On pourrait juste faire un script qui envoie 2^32 nombres jusqu'à trouver
le bon mais ca semble assez contreproductif (et je pense que ca va à l'encontre
de la consigne du bruteforcing des ressources).

À la place, on va continuer à utiliser gdb pour récupérer
la valeur de `random`.

### Exploit

J'ai commencé en mettant un point d'arrêt sur main ce qui m'a permis de voir
que l'appel à rand() était à `*main+33` et que je pourrai avoir la valeur
de rand à `*main+38`. Donc je mets un autre point d'arrêt à cet endroit et
ca donne :

```bash
random@ubuntu:~$ gdb ./random
pwndbg> b *main+38
Breakpoint 1 at 0x122f
pwndbg> r
Starting program: /home/random/random
[...]
──────────────────────────────────────────────[ DISASM / x86-64 / set emulate off ]───────────────────────────────────────────────
 ► 0x562fb674022f <main+38>    mov    dword ptr [rbp - 0x1c], eax     [0x7ffdccdba344] <= 0x6b8b4567
[...]
──────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────
 ► 0   0x562fb674022f main+38
   1   0x7f5f1cbd4d90 __libc_start_call_main+128
   2   0x7f5f1cbd4e40 __libc_start_main+128
   3   0x562fb6740145 _start+37
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

On doit donc afficher la valeur contenue dans `eax`:

```bash
pwndbg> p $eax
$1 = 1804289383
```

À partir de là, on peut faire le calcul qui est fait dans le programme pour
récupérer la `key` à passer.

```python
random@ubuntu:~$ python3 -c "print(1804289383 ^ 0xcafebabe)"
2708864985
```

### Résultat

```bash
random@ubuntu:~$ ./random
2708864985
Good!
m0mmy_I_can_predict_rand0m_v4lue!
```
