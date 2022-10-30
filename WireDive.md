# WireDive

## Info 

- Category : Digital Forensics
- SHA1SUM :	a2aa9ad4831057e17df585bdac84efc05ec0413d
- Published : Oct. 7, 2020
- Authors :	Johannes Weber and Champlain College
- Size : 26M
- Tags : Wireshark PCAP SMB Network 

Uncompress the challenge (pass: cyberdefenders.org)

Scenario :

WireDive is a combo traffic analysis exercise that contains various traces to help you understand how different protocols look on the wire.
Challenge Files:

- dhcp.pcapng
- dns.pcapng
- https.pcapng 
- network.pcapng 
- secret_sauce.txt 
- shell.pcapng 
- smb.pcapng

Tools:

- BrimSecurity
- WireShark

## 	Question

## 1 - File: dhcp.pcapng - What IP address is requested by the client ?

recherche : `dhcp`

Regarder la requête `DHCP Request > Requested IP Addresse (192.168.2.244)`

**Réponse : 192.168.2.244**

## 2 - File: dhcp.pcapng - What is the transaction ID for the DHCP release ?

recherche : `dhcp`

Regarder la requête `DHCP release > Transaction ID`

**Réponse : 0x9f8fa557**

## 3 - File: dhcp.pcapng - What is the MAC address of the client ?

recherche : `dhcp`

Regarder la requête `DHCP request > Client MAC address`

**Réponse : 00:0c:29:82:f5:94**

## 4 - File dns.pcapng - What is the response for the lookup for flag.fruitinc.xyz ?

**Réponse : ACOOLDNSFLAG**

## 5 - File: dns.pcapng - Which root server responds to the query ? Hostname.

recherche : `DNS`

On regarde la première query DNS, la réponse contient une liste de DNS Root. La seconde query a pour destination l'IP du DNS Root.

Il suffit de faire un nslookup sur 192.203.230.10

```shell

```

**Réponse : e.root-servers.net**

## 6 - File smb.pcapng - What is the path of the file that is opened ?

recherche : `smb2.create.action`

On trouve des requêtes **Create Response File : ...**

**Réponse : HelloWorld\TradeSecrets.txt**

## 7 - File smb.pcapng - What is the hex status code when the user SAMBA\jtomato logs in ?

recherche : `smb2 && ntlmssp.auth.username == jtomato || tcp.stream`

On remarque la requête `Session Setup Request, NTLMSSP_AUTH, User: SAMBA\jtomato` ainsi que sa réponse `Session Setup Response, Error: STATUS_LOGON_FAILURE`. On trouve le status code dans la réponse à la requête `SMB2 > SMB2 Header > NT Status: STATUS_LOGON_FAILURE (0xc000006d)`

**Réponse : 0xc000006d**

## 8 - File smb.pcapng - What is the tree that is being browsed ?

recherche : `smb2.tree`

On remarque la requête `Tree Connect Request Tree: \\192.168.2.10\public`

**Réponse : \\192.168.2.10\public**

## 9 - File smb.pcapng - What is the flag in the file ?

`Fichier > exporter objet > smb` : exporter **HelloWorldTradeSecrets.txt**

CTRL + F, flag : flag<OneSuperDuperSecret>

**Réponse : OneSuperDuperSecret**

## 10 - File shell.pcapng - What port is the shell listening on ?

recherche : `tcp`

On regarde le port de destination du premier paquet

**Réponse : 4444**

## 11 - File shell.pcapng - What is the port for the second shell ?

recherche : `tcp && ip.src == 192.168.2.5 && ip.dst == 192.168.2.244 && tcp.port != 4444`

On regarde le port de destination du premier paquet

**Réponse : 9999**

## 12 - File shell.pcapng - What version of netcat is installed ?

recherche : `tcp`

On regarde la première requête et `Suivre > flux TCP`.

L'attaquant install netcat sur la machine victime, on peut voir la version installé

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt update
echo "*umR@Q%4V&RC" | sudo -S apt update
[...]
18 packages can be upgraded. Run 'apt list --upgradable' to see them.
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt install netcat
echo "*umR@Q%4V&RC" | sudo -S apt install netcat
[...]
Get:1 http://us.archive.ubuntu.com/ubuntu bionic/universe amd64 netcat all 1.10-41.1 [3,436 B]
[...]
(Reading database ... 138205 files and directories currently installed.)
Preparing to unpack .../netcat_1.10-41.1_all.deb ...
Unpacking netcat (1.10-41.1) ...
Setting up netcat (1.10-41.1) ...
```

**Réponse : 1.10-41.1**

## 13 - File shell.pcapng - What file is added to the second shell

recherche : `tcp.stream eq 0`

On regarde la première requête et `Suivre > flux TCP`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S nc -nvlp 9999 < /etc/passwd
echo "*umR@Q%4V&RC" | sudo -S nc -nvlp 9999 < /etc/passwd
Listening on [0.0.0.0] (family 0, port 9999)
Connection from 192.168.2.244 34972 received!
```

**Réponse : /etc/passwd**

## 14 - File shell.pcapng - What password is used to elevate the shell ?

recherche : `tcp.stream eq 0`

On regarde la première requête et `Suivre > flux TCP`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt update
echo "*umR@Q%4V&RC" | sudo -S apt update
```

**Réponse : *umR@Q%4V&RC**

## 15 - File shell.pcapng - What is the OS version of the target system ?

recherche : `tcp.stream eq 0`

On regarde la première requête et `Suivre > flux TCP`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt update
echo "*umR@Q%4V&RC" | sudo -S apt update

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Hit:1 http://us.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://us.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://us.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 http://us.archive.ubuntu.com/ubuntu bionic-security InRelease
```

**Réponse : bionic**

## 16 - File shell.pcapng - How many users are on the target system ?

recherche : `tcp`

Dans le dernier flux (`tcp.stream eq 6`), on voit le contenu du `/etc/passwd`

```shell
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jtomato:x:1000:1000:Jim Tomamto:/home/jtomato:/bin/bash
bind:x:111:113::/var/cache/bind:/usr/sbin/nologin
```

**Réponse : 31**

## 17 - File network.pcapng - What is the IPv6 NTP server IP ?

recherche : `ntp`

Il y a seulement 1 couple de paquet en IPv6. L'IPv6 de destination est celle du serveur NTP

**Réponse : 2003:51:6012:110::dcf7:123**

## 18 - File network.pcapng - What is the first IP address that is requested by the DHCP client ?

recherche : `dhcp`

Regarder la première requête **DHCP Request** : `DHCP Request > Requested IP Addresse (192.168.20.11)`

**Réponse : 192.168.20.11**

## 19 - File network.pcapng - What is the first authoritative name server for the domain that is being queried ?

recherche : `dns`

On regarde la première requête `DNS	152	Standard query response 0xb4ca A blog.webernetz.net A 5.35.226.136 NS ns2.hans.hosteurope.de NS ns1.hans.hosteurope.de`

**Réponse : ns1.hans.hosteurope.de**

## 20 - File network.pcapng - What is the number of the first VLAN to have a topology change occur ?

recherche : `stp.flags.tc == 1` (=`Spanning Tree Protocol > BPDU flags > 1 = Topology Change: yes`)

On regarde la première requête `Spanning Tree Protocol > Originating VLAN (PVID): 20`

**Réponse : 20**

## 21 - File network.pcapng - What is the port for CDP for CCNP-LAB-S2 ?

CDP =  Cisco Discovery Protocol

recherche : `cdp`

On regarde la requête `Device ID: CCNP-LAB-S2.webernetz.net  Port ID: GigabitEthernet0/2`

`Cisco Discovery Protocol > Port ID`

**Réponse : GigabitEthernet0/2**

## 22 - File network.pcapng - What is the MAC address for the root bridge for VLAN 60 ?

recherche : `stp.pvst.origvlan == 60`

On regarde dans n'importe quelle paquet `Spanning Tree Protocol > Root Identifier > Root Bridge System ID`

**Réponse : 00:21:1b:ae:31:80**

## 23 - File network.pcapng - What is the IOS version running on CCNP-LAB-S2 ?

recherche : `cdp.deviceid == CCNP-LAB-S2.webernetz.net`

On regarde dans n'importe quelle paquet `Cisco Discovery Protocol > Software Version > Software version`

**Réponse : 12.1(22)EA14**

## 24 - File network.pcapng - What is the virtual IP address used for hsrp group 121 ?

recherche : `hsrp`

Regarder dans les requêtes `Cisco Hot Standby Router Protocol > Group State TLV > Group`. Lorsque le paquet correspond regarde le champ `Cisco Hot Standby Router Protocol > Group State TLV > Virtual IP Address`

**Réponse : 192.168.121.1**

## 27 - File network.pcapng - How many router solicitations were sent ?

recherche : `icmpv6.type == 133`

On compte le nombre de paquet

**Réponse : 3**

## 28 - File network.pcapng - What is the management address of CCNP-LAB-S2 ?

recherche : `cdp.deviceid == CCNP-LAB-S2.webernetz.net`

On regarde dans n'importe quelle paquet `Cisco Discovery Protocol > Management Addresses > IP address`

**Réponse : 192.168.121.20**

## 29 - File network.pcapng - What is the interface being reported on in the first snmp query ?

recherche : `snmp`

On regarde la première requête "get-response" `get-response 1.3.6.1.2.1...`. Puis `Simple Network Management Protocol > data: get-response > variable-bindings > 1.3.6.1.2.1.31.1.1.1.1.2: "Fa0/1"`

**Réponse : FA0/1**

## 30 - File network.pcapng - When was the NVRAM config last updated ?

`Editer > Trouver un paquet` : Taille du paquet et chaine de caractères **nvram**

On arrive sur la bonne requête `Suivre > flux UDP`

`! NVRAM config last updated at 21:02:36 UTC Fri Mar 3 2017 by weberjoh`

**Réponse : 21:02:36 03/03/2017**

## 31 - File network.pcapng - What is the ip of the radius server ?

`Editer > Trouver un paquet` : Taille du paquet et chaine de caractères **radius**

On arrive sur la bonne requête `Suivre > flux UDP`

```shell
radius server blubb
 address ipv6 2001:DB8::1812 auth-port 1812 acct-port 1813
```

**Réponse : 2001:DB8::1812**

---

Pour la suite des analyses, il faut déchiffer le flux HTTPS avec le ficher le fichier **secret_sauce.txt** SSL/TLS secrets log file, generated by NSS fournis.

Dans Wireshark `Editer > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`

---

## 32 - File https.pcapng - What has been added to web interaction with web01.fruitinc.xyz ?

recherche : `http.host == "web01.fruitinc.xyz"`

`Suivre > flux HTTP`

```
HTTP/1.1 200 OK
Date: Fri, 17 Apr 2020 18:32:24 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
Last-Modified: Fri, 17 Apr 2020 18:30:55 GMT
ETag: "41-5a380bff28e46"
Accept-Ranges: bytes
Content-Length: 65
flag: y2*Lg4cHe@Ps
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

**flag: y2*Lg4cHe@Ps**

**Réponse : y2*Lg4cHe@Ps**

## 33 - File https.pcapng - What is the name of the photo that is viewed in slack ?

recherche : `http`

`Editer > Trouver un paquet` : Taille du paquet et chaine de caractères **slack**

`Suivre > flux HTTP`

```
GET /files-tmb/TTL7QHDUJ-F011PDVK8TD-115062e5c0/get_a_new_phone_today__720.jpg HTTP/1.1
Host: files.slack.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: b=.9lmcvj9h0pwwksrwoopvfs2no; x=9lmcvj9h0pwwksrwoopvfs2no.1587148414; d=aYHLfpRRIdIGmbVSXd414fYil7oTWOkgjQIhLCnRVinnHnBo0fZd0ltopMbyUaYNj0MRqyF9BS4ZxLDUZ92xXXw5GclrJbFFPv3BIYDlErvB2NQ7MayhMGSj6hlG1pVeRS9BgZ4hl2fiwoFuAhO3w4fVngGL2LZ2jcaZ7FQC4%2FnzjaTO9A6KPoY9; d-s=1587148431; lc=1587148431
```

**Réponse : get_a_new_phone_today__720.jpg**

## 34 - File https.pcapng - What is the username and password to login to 192.168.2.1 ? Format: 'username:password' without quotes.

recherche : `ip.dst == 192.168.2.1 and urlencoded-form`

```
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "__csrf_magic" = "sid:a68a97d4f80a4ff8f25235ed57574d2979224f5a,1587148353;ip:0f813abe32d96228b630d34339938d54ca4d8077,1587148353"
        Key: __csrf_magic
        Value: sid:a68a97d4f80a4ff8f25235ed57574d2979224f5a,1587148353;ip:0f813abe32d96228b630d34339938d54ca4d8077,1587148353
    Form item: "usernamefld" = "admin"
    Form item: "passwordfld" = "Ac5R4D9iyqD5bSh"
        Key: passwordfld
        Value: Ac5R4D9iyqD5bSh
    Form item: "login" = "Sign In"
        Key: login
        Value: Sign In
```

**Réponse : admin:Ac5R4D9iyqD5bSh&**

## 35 - File https.pcapng - What is the certStatus for the certificate with a serial number of 07752cebe5222fcf5c7d2038984c5198 ?

`Editer > Trouver un paquet` : Taille du paquet et chaine de caractères **07752cebe5222fcf5c7d2038984c5198**. Regarder le **certStatus**

**Réponse : good**

## 36 - File https.pcapng - What is the email of someone who needs to change their password ?

**Réponse : jim.tomato@fruitinc.xyz**

## 37 - File https.pcapng - A service is assigned to an interface. What is the interface, and what is the service ? Format: interface_name:service_name

recherche : `http2 && ip.dst_host == 192.168.2.1`

Le paquet `POST /services_ntpd.php, WINDOW_UPDATE[45]`

On a le service et pour l'interface, on va chercher dans le pasuet suivant `HyperText Transfer Protocol 2 > MIME Multipart Media Encampsulation > Encapsulated Multipart Media > Data`

**lan = 6c616e**

(Peut être en hexadecimal)

**Réponse : lan:ntp**