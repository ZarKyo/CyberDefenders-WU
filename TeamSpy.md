# TeamSpy

## Info

Category :	Digital Forensics

SHA1SUM : 	1bc677daf51be254c8bfb9085f7375bbf1ee8e3b

Published : 	June 4, 2022

Author : 	Wyatt Roersma

Size :		1.4G

Tags :		GrrCon Memory WIndows TeamViewer


Uncompress the challenge (pass: cyberdefenders.org)


Scenario:

An employee reported that his machine started to act strangely after receiving a suspicious email with a document file. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. Analyze the dumps and help the IR team figure out what happened!

Tools:

- Volatilty 2.6
- OSTviewer
- OfficeMalScanner
- VirusTotal
- dotnetfiddle


##	Question

#### 1 - File->ecorpoffice / What is the PID the malicious file is running under?

On trouve le profil permettant d'analyser l'image m�moire � l'aide volatility :

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem imageinfo
```

Le profil de l'image est `Win7SP1x64`. En utilisant le plugin `pslist`, on peut observer les diff�rents processus.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 pslist
```

`skypeC2autoup`semble suspect. Son PID est **1364**

**R�ponse : 1364**


#### 2 - File->ecorpoffice / What is the C2 server IP address?

On r�utilise **volatility** avec le plugin **netsacn**

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 netscan
``` 

Pour voir les ports ouverts et qui �coute. `skypeC2autoup` �tabli une connexion avec l'adresse IP **54.174.131.235**

**R�ponse : 54.174.131.235**

#### 3 - File->ecorpoffice / What is the Teamviewer version abused by the malicious file?

On dump la m�moire du process et on grep � l'endroit o� �a parle de l'addresse ip

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 memdump -p 1364 -D ./output
```

```
strings -a10 -b10 1364.dmp | grep 54.174.131.235
```

On peut voir la version de `TeamViewer`.

**R�ponse : 0.2.2.2**

#### 4 - File->ecorpoffice / What password did the malicious file use to enable remote access to the system?

Pour cette question, on utilise le plugin `editbox` qui permet de voir les �l�ments afich�s par les boites de dialogue windows.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 editbox
```

Dans une des bo�tes de dialogue, il est affich� le mot de passe utilis� pour lancer le processus.

**R�ponse : P59fS93m**

#### 5 - File->ecorpoffice / What was the sender's email address that delivered the phishing email?

Il faut trouver le fichier `Outlook`contenant la bo�te mail de l'utilisateur. A l'aide du plugin **filescan**.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 filescan > output/out.txt
```

On r�cup�re l'emplacement du fichier PST en faisant :

```
cat output/out.txt | grep -i .pst
```

On a l'adresse m�moire du PST et on le dump avec volatility

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007fd38c80 -D=output/
```

On l'ouvre dans `OutlookForensicTool`.

**R�ponse :  karenmiles@t-online.de**


#### 6 - File->ecorpoffice / What is the MD5 hash of the malicious document?

Dans `OutlookForensicTool`, on t�l�charge le fichier contenu dans le mail de phishing et on calcule son hash.

**R�ponse :  c2dbf24a0dc7276a71dd0824647535c9**

#### 7 - File->ecorpoffice / What is the bitcoin wallet address that ransomware was demanded?

Regarder dans les autres mails de la victime. Un des mails contient l'adresse du portefeuille bitcoin.

**R�ponse :   25UMDkGKBe484WSj5Qd8DhK6xkMUzQFydY**

#### 8 - File->ecorpoffice / What is the ID given to the system by the malicious file for remote access?

On r�utilise `editbox` pour voir les param�tres donn�s au malware.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 editbox
```


**R�ponse : 528 812 561**


#### 9 - File->ecorpoffice / What is the IPv4 address the actor last connected to the system with the remote access tool?

On regarde les addresses ip du process puis si elles sont proches de l'utilisation de **TeamViewer**.

```
strings output/1364.dmp | grep -B 3 -A 2 -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep teamviewer -B 3 -A 3
```

**R�ponse :  31.6.13.155**


#### 10 - File->ecorpoffice / What Public Function in the word document returns the full command string that is eventually run on the system?

On r�cup�re le document Word � l'aide de OutlookForensicTool (dans les mails qu'on a pr�cedemment mis dedans).

L'outil `OfficeMalScanner`permet d'extraire les macros des documents Word. On peut ensuite analyser la macro � l'aide du site : `https://dotnetfiddle.net/`

**R�ponse : UsoJar**

#### 11 - File->ecorpwin7 / What is the MD5 hash of the malicious document?

On fait comme � la question **5**. On r�cup�re la bo�te mail qu'on analyse.

On voit que la personne re�oit un document appel� : `Important_ECORP_Lawsuit_Washington_Leak.rtf`

On se doute qu'il s'agit de ce document qui est suspect. Cependant il semble impossible de l'ouvrir normalement. Il semble corrompu.

De nombreux blocs de bytes nulls ont �t� ajout�s � la fin du document. Il faut les nettoyer et on obtient le hash du nouveau document.

**R�ponse :  00e4136876bf4c1069ab9c4fe40ed56f**



#### 12 - File->ecorpwin7 / What is the common name of the malicious file that gets loaded?"

On liste les commandes pass�es voir si des choses malicieuses ont �t� faites :

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 cmdline
```

Il y a deux commandes qui lancent des `test.dll` depuis un chemin suspect. On r�cup�re leurs adresses m�moires � l'aide de `filescan` et on les dump.

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan > output/out2.txt
```

```
cat output/out2.txt | grep -i test.dll
```

On les dump et on les upload sur VirusTotal ce qui donne la r�ponse.

**R�ponse :  PlugX **


#### 13 - File->ecorpwin7 / What password does the attacker use to stage the compressed file for exfil?

Ici il faut corr�ler plusieurs informations pour trouver ce qui semble supect.

En utilisant les plugins `cmdline` et `pslist` de **volatility**, il est possible de voir que le processus **conhost.exe** peut �tre usurp�. (Grand PID et lanc� en ligne de commandes)

On fait alors un dump de la m�moire du processus : 

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 memdump -p 3056 -D output/
```

puis on fait un grep voir si cela parle de mot de passe. Le fichier est encod� en **little endian**. Il faut alors utiliser la commande suivante :

```
strings -el output/3056.dmp | grep password
```

**R�ponse : password1234**


#### 14 - File->ecorpwin7 / What is the IP address of the c2 server for the malicious file?

On fait un `netscan` pour voir si il y a des connections avec un C2.

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 netscan
```

Le process `svchost.exe` �tabli des connexions avec une adresse IP ext�rieure

**R�ponse : 52.90.110.169**

#### 15 - File->ecorpwin7 / What is the email address that sent the phishing email?

On regarde le pst file qu'on a r�cup�r� � la question 11.

**R�ponse : lloydchung@allsafecybersec.com**


#### 16 - File->ecorpwin7 / What is the name of the deb package the attacker staged to infect the E Coin Servers?

On check les fils de `svchost.exe` � l'aide de `pstree`; 

on voit que `rundll32.exe` a le pid **2404** et est enfant de `scvhost.exe`. On dump � l'aide de `memdump` rundll32.exe

On regarde la processus pour voir si il a t�l�charg� un package  linux.

```
strings 2404.dmp | grep wget
```

**R�ponse : linuxav.deb**



