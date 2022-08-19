# Seized

## Info

Category :	Digital Forensics

SHA1SUM	:	a2c209bb3c221bc70f3418e079e2a22db3cebc53

Published :	May 28, 2022

Authors	:	2phi and Nofix

Size :		162 MB

Tags :		LINUX MEMORY CENTOS ROOTKIT

	
Unzip the challenge (pass: cyberdefenders.org), investigate this case, and answer the provided questions.

Use the latest version of Volatility, place the attached Volatility profile "Centos7.3.10.1062.zip" in the following path volatility/volatility/plugins/overlays/linux.

Scenario :

Using Volatility, utilize your memory analysis skills to Investigate the provided Linux memory snapshots and figure out attack details.

Tools:

- Volatility
- CyberChef
- grep

## Question

#### 1 - What is the CentOS version installed on the machine?

On utilise `grep` pour trouver la version de l'OS :

```
grep -a "Linux release" dump.mem 
```

**Réponse : 7.7.1908 **

#### 2 - There is a command containing a strange message in the bash history. Will you be able to read it?

On lance `volatility` en utilisant le profile Linux donné avec le challenge

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_bash 
```

On obtient le résultat suivant qui semble être la commande bizarre :

```    
2622 bash                 2020-05-07 14:56:17 UTC+0000   echo "c2hrQ1RGe2wzdHNfc3Q0cnRfdGgzXzFudjNzdF83NWNjNTU0NzZmM2RmZTE2MjlhYzYwfQo=" > y0ush0uldr34dth1s.txt
```

En traduisant le b64 on a le flag : 

**Réponse : shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60} **

#### 3 - What is the PID of the suspicious process?

On lance `volatility` en utilisant le profile Linux donné avec le challenge

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_pslist
```

On voit le PID 2854 qui est un ncat

**Réponse : 2854 **

#### 4 - The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

Avec le plugin linux_bash on voit ce qu'elles sont les commandes passées, donc ce qu'il a pu téléchargé. 

On va sur le github depuis lequel l'attaquant à téléchargé ses fichiers.

Dans un des fichiers on voit un message caché (dans snapshot.py).

**Réponse : shkCTF{th4t_w4s_4_dumb_b4ckd00r_86033c19e3f39315c00dca} **

#### 5 - What are the IP address and the port used by the attacker?

On lance `volatility` en utilisant le profile Linux donné avec le challenge. Et le plugin `netscan`

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_netscan
```

On regarde l'addr ip qui ecoute le port 12345. Car la backdoor a ouvert une connection sur ce port.

**Réponse : 192.168.49.1:12345 **

#### 6 - What is the first command that the attacker executed?

On analyse les commandes exécutées et les processus associés.

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_psaux
```

Après le ncat on voit la commande : 

**Réponse : python -c import pty; pty.spawn("/bin/bash") **

#### 7 - After changing the user password, we found that the attacker still has access. Can you find out how?

**rc.local** est un fichier permettant de lancer des actions au démarrage. 

On récup le pid de l'action de modif du fichier rc.local. Il suffit alors de le dump pour l'analyser

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_dump_map --dump-dir output/ -p 3196
```

```
strings *.vma |grep -i '.ssh'
```

**Réponse : shkCTF{rc.l0c4l_1s_funny_be2472cfaeed467ec9cab5b5a38e5fa0} **

#### 8 - What is the name of the rootkit that the attacker used?

Un rootkit la plupart du temps tente de `hook` les appels systèmes pour les modifier, pour ainsi escalder ses privilèges.

On utilise le plugin de volatility permettant de voir les appels systèmes et voir si il y a eu un `hook`

```
volatility -f dump.mem --profile=LinuxCentOS-7_7_1908-3_10_0-1062x64 linux_check_syscall | grep -i hook
```

La sortie de cette commande montre qu'il y a eu un hook provoqué par le rootkit :

**Réponse : sysemptyrect **


#### 9 - The rootkit uses crc65 encryption. What is the key?

Pour cette question on peut simplement grep le nom du rootkit dans la mémoire :

```
grep -a -i "sysemptyrect" dump.mem
```

On a alors la clé qui s'affiche

**Réponse : 1337tibbartibbar **




