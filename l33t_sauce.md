# l337 S4uc3

## Info

Category : 	Digital Forensics, Incident response 

SHA1SUM :	94ac99ef544086f0be9f5f6b00ae1a0834b0027b

Published :	Nov. 16, 2021

Author :	Wyatt Roersma

Size :		117 MB

Tags :		Wireshark PCAP Memory Network 

Uncompress the challenge (pass: cyberdefenders.org)

Scenario :

Everyone has heard of targeted attacks. Detecting these can be challenging, responding to these can be even more challenging. This scenario will test your network and host-based analysis skills to figure out the who, what, where, when, and how of this incident. There is sure to be something for all skill levels and the only thing you need to solve the challenge is some l337 S4uc3!

Tools :

- Volatility
- Wireshark
- Networkminer
- Brimsecurity

## Question

#### 1 - PCAP: Development.wse.local is a critical asset for the Wayne and Stark Enterprises, where the company stores new top-secret designs on weapons. Jon Smith has access to the website and we believe it may have been compromised, according to the IDS alert we received earlier today. First, determine the Public IP Address of the webserver?

On ouvre le pcapng à l'aide de **BrimSecurity**. On filtre sur les requêtes HTTP. 

On peut voir l'IP 172.16.0.1 qui communique avec la 172.16.0.108 pour accèder au site development.wse.local. 

Dans la réponse de l'Host on peut voir l'IP public de ce site.

**Réponse : 74.204.41.73**

#### 2 - PCAP: Alright, now we need you to determine a starting point for the timeline that will be useful in mapping out the incident. Please determine the arrival time of frame 1 in the "GrrCON.pcapng" evidence file.

On ouvre le pcapng dans Wireshark.

Dans `Statistiques > Propriétés du fichier de capture`

On a le Timestamp du premier paquet arrivé. On le converti en UTC.

**Réponse : 22:51:07 UTC**

#### 3 - PCAP: What version number of PHP is the development.wse.local server running?

On ouvre le pcapng dans Wireshark.

On utilise le filtre `ip.addr == 172.16.0.108 && http`. Car on sait que l'addresse IP du site est celle-ci.

On suit un des flux HTTP et on retrouve la version de PHP dans le champ XPowered.

**Réponse : 5.3.2**

#### 4 - PCAP: What version number of Apache is the development.wse.local web server using?

On ouvre le pcapng dans Wireshark.

On utilise le filtre `ip.addr == 172.16.0.108 && http`. Car on sait que l'addresse IP du site est celle-ci.

On suit un des flux HTTP et on retrouve la version d'apache dans le champ Server.
 
**Réponse : 2.2.14**

#### 5 - IR: What is the common name of the malware reported by the IDS alert provided?

On ouvre l'image de l'alerte IDS. On peut voir le nom de l'alerte en haut.

**Réponse : zeus**

#### 6 - PCAP: Please identify the Gateway IP address of the LAN because the infrastructure team reported a potential problem with the IDS server that could have corrupted the PCAP


On ouvre le pcapng dans Wireshark.

On peut voir beaucoup de requêtes **ARP** + **Ping** depuis la `172.16.0.1`vers d'autres addresses de ce son sous réseau.

On se doute alors qu'il s'agit de la Gateway.

**Réponse : 172.16.0.1**


#### 7 - IR: According to the IDS alert, the Zeus bot attempted to ping an external website to verify connectivity. What was the IP address of the website pinged?

On ouvre l'image de l'alerte IDS. On peut voir entre quels addresses il y a eu une alerte. Le serveur destination est la réponse.

**Réponse : 74.125.225.112**


#### 8 - PCAP: It’s critical to the infrastructure team to identify the Zeus Bot CNC server IP address so they can block communication in the firewall as soon as possible. Please provide the IP address?

On ouvre le pcapng dans Brim.

On fait la recherche suivante : 

```
event_type=="alert" | count() by alert.severity,alert.signature | sort count
```

On a une alerte qui s'appelle : `ET MALWARE Zbot POST Request to C2`

On fait une recherche avec cette valeur on voit l'addresse IP qui communique avec notre machine.

**Réponse : 88.198.6.20**

#### 9 - PCAP: The infrastructure team also requests that you identify the filename of the “.bin” configuration file that the Zeus bot downloaded right after the infection. Please provide the file name?

On ouvre le pcapng dans Wireshark.

On fait la recherche suivante : 

```
ip.addr==88.198.6.20 && http
```

On voit qu'il y a téléchargements de plusieurs fichiers dont un .bin

**Réponse : cf.bin**

#### 10 - PCAP: No other users accessed the development.wse.local WordPress site during the timeline of the incident and the reports indicate that an account successfully logged in from the external interface. Please provide the password they used to log in to the WordPress page around 6:59 PM EST?

On ouvre le pcapng dans Wireshark.

On fait la recherche suivante : 

```
ip.addr==172.16.0.108 && http
```

Dans les différentes requêtes on recherche une qui correspond à une page de login. Quand on la trouve on suit le flux HTTP.

Dans le flux 170 on voit `log=Jsmith&pwd=wM812ugu` qui est envoyé.

**Réponse : wM812ugu**

#### 11 - PCAP: After reporting that the WordPress page was indeed accessed from an external connection, your boss comes to you in a rage over the potential loss of confidential top-secret documents. He calms down enough to admit that the design's page has a separate access code outside to ensure the security of their information. Before storming off he provided the password to the designs page “1qBeJ2Az” and told you to find a timestamp of the access time or you will be fired. Please provide the time of the accessed Designs page?

On analyse le pcap dans NetworkMiner

On va dans l'onglet `Credentials` et regarder à quelle heure a été utilisé le mot de passe donné : **1qBeJ2Az**

**Réponse : 1qBeJ2Az**

#### 12 - PCAP: What is the source port number in the shellcode exploit? Dest Port was 31708 IDS Signature GPL SHELLCODE x86 inc ebx NOOP


On ouvre le pcapng dans Wireshark.

On fait la recherche suivante : 

```
udp.port == 31708
```

(ce port de destination n'apparait pas avec le protocole tcp)

#### 13 - PCAP: What was the Linux kernel version returned from the meterpreter sysinfo command run by the attacker?

On ouvre le pcapng dans Wireshark.

On fait une recherche à l'aide de `Touver un paquet`. On fait la recherche `sysinfo` dans le détail du paquet.

On suit le flux TCP du paquet trouvé et on trouve notre réponse.

**Réponse : 2.6.32-38-server**

#### 14 - PCAP: What is the value of the token passed in frame 3897?

On ouvre le pcapng dans Wireshark.

On va au paquet avec le bon numéro. On le développe et dans la catégorie **HTML Form URL Encoded** on retouve le token.

**Réponse :  b7aad621db97d56771d6316a6d0b71e9**

#### 15 - PCAP: What was the tool that was used to download a compressed file from the webserver?

On ouvre le pcapng dans Brim.

on fait la recherche pour voir les différents user agent utilisés.

```
_path=="http" | count() by user_agent
```

On vérifie bien que le user agent **wget** télécharge une archive

**Réponse : Wget**

#### 16 - PCAP: What is the download file name the user launched the Zeus bot?

Dans Wireshark : 

```
ip.addr == 88.198.6.20 && http
```

On peut voir dans les requêtes le téléchargement d'un .exe

**Réponse : bt.exe**

#### 17 - Memory: What is the full file path of the system shell spawned through the attacker's meterpreter session?

On ajoute le .zip dans le bon dossier pour avoir le bon profile de l'image mémoire.

ici

```
sudo cp DFIRwebsvr.zip /usr/local/python2.7/dist-packages/volatility/plugins/overlays/linux/
```

On peut lancer la commande suivant pour voir les shell lancés :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_psaux
```

On voit alors le shell système lancé

**Réponse : /bin/sh**

#### 18 - Memory: What is the Parent Process ID of the two 'sh' sessions?

On fait :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pstree
```

On voit que les shells sont lancés par un apache2.

**Réponse : 1042**

#### 19 - Memory: What is the latency_record_count for PID 1274?

On fait :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pslist
```

Cela permet de récupérer l'offset du processus du shell malveillant : **0xffff880006dd8000**


```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_volshell
```

et on lance `dt("task_struct",0xffff880006dd8000)`. Pour avoir les infos sur le process.


**Réponse : 0**

#### 20 - Memory: For the PID 1274, what is the first mapped file path?

On lance :


```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_proc_maps
```

On regarde au PID 1274 et le premier est.

**Réponse : /bin/dash**

#### 21 - Memory:What is the md5hash of the receive.1105.3 file out of the per-process packet queue?

On lance :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pkt_queues -D output/
```

et on fait :

```
md5sum output/receive.1105.3
```

**Réponse : 184c8748cfcfe8c0e24d7d80cac6e9bd**


