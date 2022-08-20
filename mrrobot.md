# MrRobot

## Info

Category : 	Digital Forensics

SHA1SUM	:	b8dab80336c37688f276bfbfac0ac1681398a30d

Published :	May 18, 2022

Author :	Wyatt Roersma

Size :		1.1 GB

Tags :		PHISHINGWINDOWSMEMORYRAT


Scenario :

An employee reported that his machine started to act strangely after receiving a suspicious email for a security update. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. Analyze the dumps and help the IR team figure out what happened!

Tools :

- Volatility2
- Volatility3
- Rstudio


## Question


#### 1 - Machine:Target1 / What email address tricked the front desk employee into installing a security update?

On fait un string sur l'image mémoire pour voir si on arrive à voir des addresses mails.

```
strings Target1.vmss | egrep '([[:alnum:]_.-]{1,64}+@[[:alnum:]_.-]{2,255}+?\.[[:alpha:].]{2,4})'
```

**Réponse :  th3wh1t3r0s3@gmail.com**

#### 2 - What is the filename that was delivered in the email?

De même mais en regardant autour de l'addresse mail vu précédemment voir le mail qui a été reçu

```
strings Target1-1dd8701f.vmss | grep -i TH3WH1T3R0S3@GMAIL.COM -a5
```

**Réponse : AnyConnectInstaller.exe**


#### 3 - What is the name of the rat's family used by the attacker?

On récupère la liste des fichiers chargés en mémoire

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 filescan > filescan.txt
```

On récupère l'addresse mémoire du malware pour le dump juste après :

```
cat filescan.txt | grep AnyConnectInstaller.exe
```

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003ed57968 -D output/
```

On met le hash sur virustotal

**Réponse : XTREMERAT**

#### 4 - The malware appears to be leveraging process injection. What is the PID of the process that is injected?

En mettant le hash sur VirusTotal, on voit dans la catégorie **Process Injected** qu'il s'injecte dans IE Explorer.

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 pslit
```

Pour lister les process et leurs PID

**Réponse : 2996**

#### 5 - What is the unique value the malware is using to maintain persistence after reboot?

VirusTotal donne la valeur de la clé run utilisée par le malware

**Réponse : MrRobot**


#### 6 - Malware often uses a unique value or name to ensure that only one copy runs on the system. What is the unique name the malware is using?

Les mutants sont utilisés pour savoir lorsqu'une machinee est infectée ou non

On peut lister les **handles** du process infecté et voir si il y a des mutants 

```
vol.py -f Target1.dmp --profile=Win7SP1x86_23418 handles -p 2996 | grep -i mutant
```

**Réponse : fsociety0.dat**

#### 7 - It appears that a notorious hacker compromised this box before our current attackers. Name the movie he or she is from.

Question assez particulière mais en regardant la liste des utilisateurs présents sur la machine on peut trouver le nom du film :


```
vol.py -f Target1.dmp --profile=Win7SP1x86_23418 cachedump
```
Un des utilisateurs s'appelle **zerocool** comme dans le film :

**Réponse : hackers**

#### 8 - Machine:Target1 / What is the NTLM password hash for the administrator account?

On utilise le plugin `hashdump` pour récupèrer des hash de l'image mémoire

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 hashdump
```

**Réponse : 79402b7671c317877b8b954b3311fa82**


#### 9 - The attackers appear to have moved over some tools to the compromised front desk host. How many tools did the attacker move?

On utilise le plugin `consoles` de volatility pour voir l'historique des commandes passées

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 consoles
```

On peut voir la liste des exécutables suspect dans le dossier **Tmp**.

**Réponse : 3**


#### 10 - What is the password for the front desk local administrator account?

Pareil

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 consoles
```

l'outil wce a été utilisé et montre le mdp.

**Réponse : flagadmin@1234**

#### 11 -  What is the std create data timestamp for the nbtscan.exe tool?

On récupère la MFT de l'image mémoire qui est la liste des fichiers avec leurs dates de modif+création

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 mftparser > mft.txt
```

```
cat mft.txt | grep nbtscan.exe
```

**Réponse : 2015-10-09 10:45:12 UTC**

#### 12 - The attackers appear to have stored the output from the nbtscan.exe tool in a text file on a disk called nbs.txt. What is the IP address of the first machine in that file?

On récupère le fichier à l'aide de volatility :

```
cat filescan.txt | grep nbs.txt
```
```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003fdb7808 -D output/
```
```
cat output/file.None.0x83eda598.dat
```

**Réponse : 10.1.1.2**


#### 13 - What is the full IP address and the port was the attacker's malware using?

On liste les connexions faites par la machine

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 netscan
```

**Réponse : 180.76.254.120:22**

#### 14 - It appears the attacker also installed legit remote administration software. What is the name of the running process?

En listant les différences process à l'aide du plugin `pslist`, on voit un logiciel bien connu

**Réponse : TeamViewer.exe**

#### 15 - It appears the attackers also used a built-in remote access method. What IP address did they connect to?

En réutilisant le plugin `netscan` on peut voir les connections

**Réponse : 10.1.1.21** 

#### 16 - Machine:Target2 / It appears the attacker moved latterly from the front desk machine to the security admins (Gideon) machine and dumped the passwords. What is Gideon's password?

En utilisant le plugin `consoles` on voit l'historique :

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

l'utilitaire wce a écrit sa sortie sur le fichier `w.tmp`. On le dump

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 filescan > filescan.txt
```
```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003fcf2798 -D output/
```
```
cat output/file.None.0x85a35da0.dat
```

Et on récupère le mot de passe

**Réponse : t76fRJhS**

#### 17 - Once the attacker gained access to "Gideon," they pivoted to the AllSafeCyberSec domain controller to steal files. It appears they were successful. What password did they use?

On regarde l'historique des commandes et on voit le mot de passe utilisé

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

**Réponse : 123qwe!@#** 

#### 18 - What was the name of the RAR file created by the attackers?

Même chose on regarde l'historique des commandes :

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

**Réponse : crownjewlez.rar**


#### 19 - How many files did the attacker add to the RAR archive?

On regarde le pid fu process qui s'est connecté au DC (conhost)
```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 pslist (on regarde le pid du process qui s'est co au dc conhost)
```

On dump le process et on regarde si il y a la création du .rar dedans

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 memdump -p 3048 -D output/
```
```
strings -e l output/3048.dmp | grep -i crownjewlez.rar -A10 -B10
```

**Réponse : 3**



#### 20 - The attacker appears to have created a scheduled task on Gideon's machine. What is the name of the file associated with the scheduled task?

On liste les scheduled tasks 

```
cat filescan.txt | grep -i “System32\\\tasks\\\\”
```

Une des taches semblent suspectes : **At1**

On la dump et on cat le fichier.

**Réponse : 1.dat**


#### 22 - Machine:POS / What is the malware CNC's server?

On regarde les connexions de la machine ers l'extérieur :

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86_23418 netscan
```

**Réponse : 54.84.237.92**


#### 23 - What is the common name of the malware used to infect the POS system?

On utilise le plugin `malfind` de volatility pour voir si il trouve quelque chose :

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86_23418 malfind -p 3208 -D output/
```

On récupère le malware du processus infecté puis VirusTotal

**Réponse : Dexter**


#### 23 - In the POS malware whitelist. What application was specific to Allsafecybersec?

On dump les dll utilisées à l'addresse mémoire du processu malveillant

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86 dlldump -p 3208 --base=0x50000 -D ./
```

On regarde ses chaines de caractères.

```
strings module.3208.3fd324d8.50000.dll | grep -i exe"  
```

**Réponse : allsafe_protector.exe**

#### 24 - What is the name of the file the malware was initially launched from?

En utilisant le plugin `iehistory` on peut voir quel executable répond à la question

**Réponse : allsafe_update.exe**










