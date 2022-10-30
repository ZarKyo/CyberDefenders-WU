# HawkEye

## Info
 
- Category : Digital Forensics, Malware Analysis 
- SHA1SUM :	bd7239a7c1e33f4d616242fe892888befc9fashed 
- Published : March 3, 2022 
- Authors : Brad Duncan and Manuel GRegal 
- Size : 1.3 MB 
- Tags : PCAP WireShark Network BRIM 

Uncompress the challenge (pass: cyberdefenders.org) 

Scenario:

An accountant at your organization received an email regarding an invoice with a download link. Suspicious network traffic was observed shortly after opening the email. As a SOC analyst, investigate the network trace and analyze exfiltration attempts.

Tools:

- Wireshark
- BrimSecurity
- Apackets
- MaxMind Geo IP
- VirusTotal

## 	Question 

#### 1 - How many packets does the capture have ?
 
`Statistiques > propriétés du fichier > paquets capturés` : 4003

**Réponse : 4003**

#### 2 - At what time was the first packet captured ?

`Vue > Format Affichage Heure > heure du jour UTC`

`Statistiques > propriétés du fichier > premier paquets` : 2019-04-10 20:37:07 UTC

**Réponse : 2019-04-10 20:37:07 UTC**

#### 3 - What is the duration of the capture ?

`Statistiques > propriétés du fichier > temps écoulé` : 01:03:41

**Réponse : 01:03:41**

#### 4 - What is the most active computer at the link level ?

`Statistiques > endpoint > ethernet` : 00:08:02:1c:47:ae

**Réponse : 00:08:02:1c:47:ae**

#### 5 - Manufacturer of the NIC of the most active system at the link level ?

`Statistiques > adresses résolues` filtre sur 00:08:02:1c:47:ae : HewlettP_1c:47:ae 

**Réponse : Hewlett-packard**

#### 6 - Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

**Réponse : Palo Alto**

#### 7 - The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture ?

`Statistiques > endpoints > ipv4` il y a 4 IPs privées en 10.4.10.0/24 mais la 10.4.10.255 est l'adresse de broadcast 

**Réponse : 3**

#### 8 - What is the name of the most active computer at the network level ?

On a remarqué précédement que le PC le plus actif est celui avce l'IP 10.4.10.132

recherche : `ip.addr == 10.4.10.132 && dhcp`

On regarde le paquet DHCP Inform

**Réponse : Beijing-5cd1-PC**

#### 9 - What is the IP of the organization's DNS server ?

recherche : `ip.addr == 10.4.10.132 && dns`

On remarque rapidement l'ip du DNS 10.4.10.4

**Réponse : 10.4.10.4**

#### 10 - What domain is the victim asking about in packet 204 ?

`Aller > Aller au paquet > 204`

Regarder le champs : `Queries`

**Réponse : proforma-invoices.com**

#### 11 - What is the IP of the domain in the previous question ?

On regarde la **réponse du paquet 204

Regarder le champs : `Queries > Answers`

**Réponse : 217.182.138.150**

#### 12 - Indicate the country to which the IP in the previous section belongs.

Avec Geoip, l'IP vient de France

**Réponse : France**

#### 13 - What operating system does the victim's computer run ?

On regarde les paquets http, puis `Suivre > flux TCP`. Dans le 

`User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)`

**Réponse : Windows NT 6.1**

#### 14 - What is the name of the malicious file downloaded by the accountant ?

On regarde les paquets http, on remarque une requêtes GET `GET /proforma/tkraw_Protected99.exe`

**Réponse : tkraw_Protected99.exe**

#### 15 - What is the md5 hash of the downloaded file ?

`Fichier > exporter objets > http` et on exporte l'exe

```shell
md5sum tkraw_Protected99.exe 
71826ba081e303866ce2a2534491a2f7  tkraw_Protected99.exe
```

**Réponse : 71826ba081e303866ce2a2534491a2f7**

#### 16 - What is the name of the malware according to Malwarebytes ?

Mettre l'exe dans VT

**Réponse : Spyware.HawkEyeKeyLogger**

#### 17 - What software runs the webserver that hosts the malware ?

Recherche : `ip.addr == 10.4.10.132 && http `

`Suivre > Flux TCP` et regarder le header d'une requête HTTP provenant du server

**Réponse :LiteSpeed**

#### 18 - What is the public IP of the victim's computer ?

Recherche : `ip.addr == 10.4.10.132 && http`

Des requêtes sont envoyé à http://bot.whatismyipaddress.com et on regarde les réponses de ces requêtes

**Réponse : 173.66.146.112**

#### 19 - In which country is the email server to which the stolen information is sent ?

Recherche : `ip.addr == 10.4.10.132 && smtp`

On remarque une communication avec un serveur de mail avec l'IP 23.229.162.69

`Statistiques > endpoints > IPv4 23.229.162.69`: Country = United States

Ou

```shell
whois 23.229.162.69

[...]
Country:        US
[...]
```

**Réponse : United States**

#### 20 - What is the domain's creation date to which the information is exfiltrated ?

```shell
whois macwinlogistics.in

Domain Name: macwinlogistics.in
Registry Domain ID: D8113179-IN
Registrar WHOIS Server:
Registrar URL: www.godaddy.com
Updated Date: 2022-02-16T07:01:27Z
Creation Date: 2014-02-08T10:31:26Z
Registry Expiry Date: 2023-02-08T10:31:26Z
```

**Réponse : 2014-02-08**

#### 21 - Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent ?

Recherche : `ip.addr == 10.4.10.132 && smtp`

`Suivre > flux TCP`, on regarde le message envoyé par le serveur

**Réponse : Exim 4.91**

#### 22 - To which email account is the stolen information sent ?

Recherche : `ip.addr == 10.4.10.132 && smtp`

`Suivre > flux TCP`, on regarde le **RCPT TO**

**Réponse : sales.del@macwinlogistics.in**

#### 23 - What is the password used by the malware to send the email ?

Recherche : `ip.addr == 10.4.10.132 && smtp`

`Suivre > flux TCP`, on regarde l'échange au niveau de l'authentification

```shell
echo U2FsZXNAMjM= | base64 -d
Sales@23
```

**Réponse :Sales@23**

#### 24 - Which malware variant exfiltrated the data ?

Recherche : `ip.addr == 10.4.10.132 && smtp`

`Suivre > flux TCP`, on remarque un gros bloc de base64 dans le mail

```shell
echo SGF3a0V5ZSBLZXlsb2dnZXIgLSBSZWJvcm4gdjkgLSBQYXNzd29yZHMgTG9ncyAtIHJvbWFuLm1jZ3VpcmUgXCBCRUlKSU5HLTVDRDEtUEMgLSAxNzMuNjYuMTQ2LjExMg== | base64 -d
HawkEye Keylogger - Reborn v9 - Passwords Logs - roman.mcguire \ BEIJING-5CD1-PC - 173.66.146.112
```

**Réponse : Reborn v9**

#### 25 - What are the bankofamerica access credentials ? (username:password)

```shell
base64 -d encode.txt

[...]
==================================================
URL               : https://www.bankofamerica.com/
Web Browser       : Chrome
User Name         : roman.mcguire
Password          : P@ssw0rd$
Password Strength : Very Strong
User Name Field   : onlineId1
Password Field    : passcode1
Created Time      : 4/10/2019 2:35:17 AM
Modified Time     : 
Filename          : C:\Users\roman.mcguire\AppData\Local\Google\Chrome\User Data\Default\Login Data
==================================================
[...]
```

**Réponse : roman.mcguire:P@ssw0rd$**

#### 26 - Every how many minutes does the collected data get exfiltrated ?

Recherche : `ip.addr == 10.4.10.132 && smtp.req.command == "EHLO"`

On remarque une requête toute les 10min

**Réponse : 10**
