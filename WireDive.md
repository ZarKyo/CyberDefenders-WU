# WireDive

## Info 

- Category : 	Digital Forensics
- SHA1SUM :	a2aa9ad4831057e17df585bdac84efc05ec0413d
- Published :	Oct. 7, 2020
- Authors :	Johannes Weber and Champlain College
- Size :		26M
- Tags :		Wireshark PCAP SMB Network 		

Uncompress the challenge (pass: cyberdefenders.org)

### Scenario

WireDive is a combo traffic analysis exercise that contains various traces to help you understand how different protocols look on the wire.
Challenge Files :

- dhcp.pcapng
- dns.pcapng
- https.pcapng 
- network.pcapng 
- secret_sauce.txt 
- shell.pcapng 
- smb.pcapng

### Tools

- BrimSecurity
- WireShark

---

## Questions

### 1 - File: dhcp.pcapng - What IP address is requested by the client ?

search: `dhcp`

Look at the query `DHCP Request > Requested IP Address (192.168.2.244)`

**Answer: 192.168.2.244**

### 2 - File: dhcp.pcapng - What is the transaction ID for the DHCP release?

search: `dhcp`

Look at the `DHCP release > Transaction ID` request

**Answer: 0x9f8fa557**

### 3 - File: dhcp.pcapng - What is the MAC address of the client?

search: `dhcp`

Look at the request `DHCP request > Client MAC address`

**Answer: 00:0c:29:82:f5:94**

### 4 - File dns.pcapng - What is the response for the lookup for flag.fruitinc.xyz?

**Answer: ACOOLDNSFLAG**

### 5 - File: dns.pcapng - Which root server responds to the query? Hostname.

search: `DNS`

We look at the first DNS query, the response contains a list of DNS Root. The second query is for the DNS Root IP.

Just do an nslookup on 192.203.230.10

```shell
nslookup 192.203.230.10               
10.230.203.192.in-addr.arpa     name = e.root-servers.net.
```

**Answer: e.root-servers.net**

### 6 - File smb.pcapng - What is the path of the file that is opened?

search: `smb2.create.action`

There are requests **Create Response File: ...**

**Answer: HelloWorld\TradeSecrets.txt**

### 7 - File smb.pcapng - What is the hex status code when the user SAMBA\jtomato logs in?

search: `smb2 && ntlmssp.auth.username == jtomato || tcp.stream`

We notice the request `Session Setup Request, NTLMSSP_AUTH, User: SAMBA\jtomato` as well as its response `Session Setup Response, Error: STATUS_LOGON_FAILURE`. The status code can be found in the response to the request `SMB2 > SMB2 Header > NT Status: STATUS_LOGON_FAILURE (0xc000006d)`

**Response: 0xc000006d**

### 8 - File smb.pcapng - What is the tree that is being browsed?

search: `smb2.tree`

We notice the request `Tree Connect Request Tree: \\192.168.2.10\public`

**Answer: \\192.168.2.10\public**

### 9 - File smb.pcapng - What is the flag in the file?

`File > export object > smb`: export **HelloWorldTradeSecrets.txt**

CTRL+F, flag: flag<OneSuperDuperSecret>

**Answer: OneSuperDuperSecret**

### 10 - File shell.pcapng - What port is the shell listening on?

search: `tcp`

We look at the destination port of the first packet

**Answer: 4444**

### 11 - File shell.pcapng - What is the port for the second shell ?

search: `tcp && ip.src == 192.168.2.5 && ip.dst == 192.168.2.244 && tcp.port != 4444`

We look at the destination port of the first packet

**Answer: 9999**

### 12 - File shell.pcapng - What version of netcat is installed?

search: `tcp`

We look at the first request and `Follow > TCP stream`.

The attacker install netcat on the victim machine, we can see the installed version

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

**Answer: 1.10-41.1**

### 13 - File shell.pcapng - What file is added to the second shell

search: `tcp.stream eq 0`

We look at the first request and `Follow > TCP stream`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S nc -nvlp 9999 < /etc/passwd
echo "*umR@Q%4V&RC" | sudo -S nc -nvlp 9999 < /etc/passwd
Listening on [0.0.0.0] (family 0, port 9999)
Connection from 192.168.2.244 34972 received!
```

**Answer: /etc/passwd**

### 14 - File shell.pcapng - What password is used to elevate the shell?

search: `tcp.stream eq 0`

We look at the first request and `Follow > TCP stream`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt update
echo "*umR@Q%4V&RC" | sudo -S apt update
```

**Answer: *umR@Q%4V&RC**

### 15 - File shell.pcapng - What is the OS version of the target system?

search: `tcp.stream eq 0`

We look at the first request and `Follow > TCP stream`.

```shell
jtomato@ns01:~$ echo "*umR@Q%4V&RC" | sudo -S apt update
echo "*umR@Q%4V&RC" | sudo -S apt update

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Hit:1 http://us.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://us.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://us.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 http://us.archive.ubuntu.com/ubuntu bionic-security InRelease
```

**Answer: bionic**

### 16 - File shell.pcapng - How many users are on the target system?

search: `tcp`

In the last stream (`tcp.stream eq 6`), we see the content of `/etc/passwd`

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

**Answer : 31**

### 17 - File network.pcapng - What is the IPv6 NTP server IP ?

search: `ntp`

There is only 1 packet pair in IPv6. The destination IPv6 is that of the NTP server

**Answer: 2003:51:6012:110::dcf7:123**

### 18 - File network.pcapng - What is the first IP address that is requested by the DHCP client?

search: `dhcp`

Look at the first **DHCP Request**: `DHCP Request > Requested IP Address (192.168.20.11)`

**Answer: 192.168.20.11**

### 19 - File network.pcapng - What is the first authoritative name server for the domain that is being queried?

search: `dns`

We look at the first query `DNS 152 Standard query response 0xb4ca A blog.webernetz.net A 5.35.226.136 NS ns2.hans.hosteurope.de NS ns1.hans.hosteurope.de`

**Answer: ns1.hans.hosteurope.de**

### 20 - File network.pcapng - What is the number of the first VLAN to have a topology change occur?

search: `stp.flags.tc == 1` (=`Spanning Tree Protocol > BPDU flags > 1 = Topology Change: yes`)

We look at the first request `Spanning Tree Protocol > Originating VLAN (PVID): 20`

**Answer: 20**

### 21 - File network.pcapng - What is the port for CDP for CCNP-LAB-S2?

CDP = Cisco Discovery Protocol

search: `cdp`

We look at the request `Device ID: CCNP-LAB-S2.webernetz.net Port ID: GigabitEthernet0/2`

`Cisco Discovery Protocol > Port ID`

**Answer : GigabitEthernet0/2**

### 22 - File network.pcapng - What is the MAC address for the root bridge for VLAN 60 ?

search: `stp.pvst.origvlan == 60`

We look in any package `Spanning Tree Protocol > Root Identifier > Root Bridge System ID`

**Answer: 00:21:1b:ae:31:80**

### 23 - File network.pcapng - What is the IOS version running on CCNP-LAB-S2?

search: `cdp.deviceid == CCNP-LAB-S2.webernetz.net`

We look in any package `Cisco Discovery Protocol > Software Version > Software version`

**Answer: 12.1(22)EA14**

### 24 - File network.pcapng - What is the virtual IP address used for hsrp group 121?

search: `hsrp`

Look in the `Cisco Hot Standby Router Protocol > Group State TLV > Group` queries. When the packet matches look at the field `Cisco Hot Standby Router Protocol > Group State TLV > Virtual IP Address`

**Answer: 192.168.121.1**

### 27 - File network.pcapng - How many router solicitations were sent?

search: `icmpv6.type == 133`

Count the number of packets

**Answer: 3**

### 28 - File network.pcapng - What is the management address of CCNP-LAB-S2?

search: `cdp.deviceid == CCNP-LAB-S2.webernetz.net`

We look in any packet `Cisco Discovery Protocol > Management Addresses > IP address`

**Answer: 192.168.121.20**

### 29 - File network.pcapng - What is the interface being reported on in the first snmp query?

search: `snmp`

We look at the first request "get-response" `get-response 1.3.6.1.2.1...`. Then `Simple Network Management Protocol > data: get-response > variable-bindings > 1.3.6.1.2.1.31.1.1.1.1.2: "Fa0/1"`

**Answer: FA0/1**

### 30 - File network.pcapng - When was the NVRAM config last updated?

`Edit > Find a package`: Package size and **nvram** string

We arrive on the right request `Follow > UDP stream`

`! NVRAM config last updated at 21:02:36 UTC Fri Mar 3 2017 by weberjoh`

**Answer: 21:02:36 03/03/2017**

### 31 - File network.pcapng - What is the ip of the radius server?

`Edit > Find a package`: Package size and string **radius**

We arrive on the right request `Follow > UDP stream`

```shell
radius server blubb
 address ipv6 2001:DB8::1812 auth-port 1812 acct-port 1813
```

**Answer: 2001:DB8::1812**

---

For further analyses, the HTTPS stream must be decrypted with the file **secret_sauce.txt** SSL/TLS secrets log file, generated by NSS provided.

In Wireshark `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`

---

### 32 - File https.pcapng - What has been added to web interaction with web01.fruitinc.xyz ?

search: `http.host == "web01.fruitinc.xyz"`

`Follow > HTTP stream`

```
HTTP/1.1 200 OK
Date: Fri, 17 Apr 2020 18:32:24 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
Last-Modified: Fri, 17 Apr 2020 18:30:55 GMT
ETag: "41-5a380bff28e46"
Accept-Ranges: bytes
Content Length: 65
flag: y2*Lg4cHe@Ps
Keep-Alive: timeout=5, max=100
Connection: Keep Alive
Content-Type: text/html; charset=UTF-8
```

**flag: y2*Lg4cHe@Ps**

**Answer: y2*Lg4cHe@Ps**

### 33 - File https.pcapng - What is the name of the photo that is viewed in slack?

search: `http`

`Edit > Find a package`: Package size and string **slack**

`Follow > HTTP stream`

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

**Answer: get_a_new_phone_today__720.jpg**

### 34 - File https.pcapng - What is the username and password to login to 192.168.2.1? Format: 'username:password' without quotes.

search: `ip.dst == 192.168.2.1 and urlencoded-form`

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

**Answer: admin:Ac5R4D9iyqD5bSh&**

### 35 - File https.pcapng - What is the certStatus for the certificate with a serial number of 07752cebe5222fcf5c7d2038984c5198?

`Edit > Find a package`: Package size and string **07752cebe5222fcf5c7d2038984c5198**. Look at the **certStatus**

**Answer: good**

### 36 - File https.pcapng - What is the email of someone who needs to change their password?

**Answer: jim.tomato@fruitinc.xyz**

### 37 - File https.pcapng - A service is assigned to an interface. What is the interface, and what is the service? Format: interface_name:service_name

search: `http2 && ip.dst_host == 192.168.2.1`

The `POST /services_ntpd.php, WINDOW_UPDATE[45]` package

We have the service and for the interface, we will look in the following step `HyperText Transfer Protocol 2 > MIME Multipart Media Encampsulation > Encapsulated Multipart Media > Data`

**lan = 6c616e**

(May be in hexadecimal)

**Answer: lan:ntp**
