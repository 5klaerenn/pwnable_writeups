# Collision

## Description

Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

"ssh <col@pwnable.kr> -p2222 (pw:guest)"

## Writeup

flag:

Même principe que toujours, quand on arrive sur un serveur, on regarde ce
qui se trouve là :

```bash
col@ubuntu:~$ ls -la
total 44
drwxr-x---   5 root col      4096 Apr  2  2025 .
drwxr-xr-x 118 root root     4096 Jun  1  2025 ..
d---------   2 root root     4096 Jun 12  2014 .bash_history
-r-xr-sr-x   1 root col_pwn 15164 Mar 26  2025 col
-rw-r--r--   1 root root      589 Mar 26  2025 col.c
-r--r-----   1 root col_pwn    26 Apr  2  2025 flag
dr-xr-xr-x   2 root root     4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
```

Comme pour le précédent, aucune chance qu'on puisse lire directement le
flag. On va plutôt regarder le programme C.

```Clang
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
 int* ip = (int*)p;
 int i;
 int res=0;
 for(i=0; i<5; i++){
  res += ip[i];
 }
 return res;
}

int main(int argc, char* argv[]){
 if(argc<2){
  printf("usage : %s [passcode]\n", argv[0]);
  return 0;
 }
 if(strlen(argv[1]) != 20){
  printf("passcode length should be 20 bytes\n");
  return 0;
 }

 if(hashcode == check_password( argv[1] )){
  setregid(getegid(), getegid());
  system("/bin/cat flag");
  return 0;
 }
 else
  printf("wrong passcode.\n");
 return 0;
}
```

Ce qu'on lit ici c'est :

* On définit un hashcode en hexadécimal (0x21DD09EC = 568134124)
* On fait une méthode de vérification de mot de passe qui prend une chaîne
de caractères `p` en paramètres
* On instancie un pointeur `ip` de type int auquel on donne la valeur de
`(int*) p`. Comme un char fait 1byte et un int en fait 4, on peut imaginer
que la chaîne de caractères va être traitée comme un tableau de 5 entiers
(4 * 5 = 20)
* Cette intuition est confirmée quand on voit la boucle qui suit dans laquelle
on va itérer à travers 5 entiers pour les additionner.

Si on lit plus loin dans le `main`, on peut voir qu'on va ensuite comparer
le mot de passe qu'on passe en paramètre à ce qui est hashé.

La solution qui semble la plus directe serait de diviser 0x21DD09EC par 5
et d'additionner le reste.
Quand on fait `0x21DD09EC % 5 = 4`.
On ajoutera donc 4 à la 5ème occurence.

On a donc 0x21DD09EC = 0x06C5CEC8 * 4 + 0x06C5CECC

```bash
col@ubuntu:~$ ./col \x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xCC
passcode length should be 20 bytes
```

J'en déduis que ca ne fonctionne pas parce que `\x` sont interprétés
littéralement.

```bash
col@ubuntu:~$ ./col $(printf '\x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xC8\x06\xC5\xCE\xCC')
wrong passcode.
```

Pas le bon password mais on a la bonne longueur !
Comme ce sont des hexadécimaux, peut-être que c'est une question de endianess
pour déterminer l'ordre dans lequel sont lus les nombres. Et si je m'étais
souvenue de mes cours d'assembleur plus tôt, je me serais rappelée que les
architectures modernes sont en little-endian, avec le stockage des octets de
poids faible en premier.

Donc : (et profitons-en pour éviter d'avoir à se répéter trop)

```bash
col@ubuntu:~$ ./col $(printf '\xC8\xCE\xC5\x06%.0s' {1..4})$(printf '\xCC\xCE\xC5\x06')
Two_hash_collision_Nicely
```
