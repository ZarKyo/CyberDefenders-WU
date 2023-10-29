# HawkEye

## Info
 
- Category : Digital Forensics, Malware Analysis 
- SHA1SUM :	bd7239a7c1e33f4d616242fe892888befc9fashed 
- Published : March 3, 2022 
- Authors : Brad Duncan and Manuel GRegal 
- Size : 1.3 MB 
- Tags : PCAP WireShark Network BRIM 

Uncompress the challenge (pass: cyberdefenders.org) 

### Scenario

An accountant at your organization received an email regarding an invoice with a download link. Suspicious network traffic was observed shortly after opening the email. As a SOC analyst, investigate the network trace and analyze exfiltration attempts.

### Tools

- Wireshark
- BrimSecurity
- Apackets
- MaxMind Geo IP
- VirusTotal

---

## Questions 

### 1 - How many packets does the capture have ?
 
`Statistics > file properties > captured packets` : 4003

**Answer : 4003**

### 2 - At what time was the first packet captured ?

`View > Time Display Format > UTC time of day`

`Statistics > file properties > first packages` : 2019-04-10 20:37:07 UTC

**Answer : 2019-04-10 20:37:07 UTC**

### 3 - What is the duration of the capture ?

`Statistics > file properties > elapsed time` : 01:03:41

**Answer : 01:03:41**

### 4 - What is the most active computer at the link level ?

`Statistics > endpoint > ethernet` : 00:08:02:1c:47:ae

**Answer : 00:08:02:1c:47:ae**

### 5 - Manufacturer of the NIC of the most active system at the link level ?

`Statistics > resolved addresses` filter on 00:08:02:1c:47:ae : HewlettP_1c:47:ae 

**Answer : Hewlett-packard**

### 6 - Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

**Answer : Palo Alto**

### 7 - The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture ?

`Statistics > endpoints > ipv4` there are 4 private IPs in 10.4.10.0/24 but 10.4.10.255 is the broadcast address

**Answer : 3**

### 8 - What is the name of the most active computer at the network level ?

We noticed previously that the most active PC is the one with the IP 10.4.10.132 

search: `ip.addr == 10.4.10.132 && dhcp` 

We look at the DHCP Inform packet

**Answer : Beijing-5cd1-PC**

### 9 - What is the IP of the organization's DNS server ?

search: `ip.addr == 10.4.10.132 && dns`

We quickly notice the ip of the DNS 10.4.10.4

**Answer : 10.4.10.4**

### 10 - What domain is the victim asking about in packet 204 ?

`Go > Go to package > 204`

Look at the field: `Queries`

**Answer : proforma-invoices.com**

### 11 - What is the IP of the domain in the previous question ?

We look at the **Answer of package 204

Look at the field: `Queries > Answers`

**Answer : 217.182.138.150**

### 12 - Indicate the country to which the IP in the previous section belongs.

With Geoip, the IP comes from France

**Answer : France**

### 13 - What operating system does the victim's computer run ?

We look at the http packets, then `Follow > TCP stream`. In the user-agent

`User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)`

**Answer : Windows NT 6.1**

### 14 - What is the name of the malicious file downloaded by the accountant ?

We look at the http packages, we notice a GET request `GET /proforma/tkraw_Protected99.exe`

**Answer : tkraw_Protected99.exe**

### 15 - What is the md5 hash of the downloaded file ?

`File > export objects > http` and we export the exe

```shell
md5sum tkraw_Protected99.exe 
71826ba081e303866ce2a2534491a2f7  tkraw_Protected99.exe
```

**Answer : 71826ba081e303866ce2a2534491a2f7**

### 16 - What is the name of the malware according to Malwarebytes ?

Put the exe in VT (Virus Total)

**Answer : Spyware.HawkEyeKeyLogger**

### 17 - What software runs the webserver that hosts the malware ?

Search: `ip.addr == 10.4.10.132 && http `

`Follow > TCP stream` and watch the header of an HTTP request coming from the server

**Answer :LiteSpeed**

### 18 - What is the public IP of the victim's computer ?

Search: `ip.addr == 10.4.10.132 && http`

Requests are sent to http://bot.whatismyipaddress.com and we look at the Answers of these requests

**Answer : 173.66.146.112**

### 19 - In which country is the email server to which the stolen information is sent ?

Search: `ip.addr == 10.4.10.132 && smtp`

We notice a communication with a mail server with the IP 23.229.162.69

`Statistics > endpoints > IPv4 23.229.162.69`: Country = United States

Or

```shell
whois 23.229.162.69

[...]
Country:        US
[...]
```

**Answer : United States**

### 20 - What is the domain's creation date to which the information is exfiltrated ?

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

**Answer : 2014-02-08**

### 21 - Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent ?

Search: `ip.addr == 10.4.10.132 && smtp`

`Follow > TCP stream`, we look at the message sent by the server

**Answer : Exim 4.91**

### 22 - To which email account is the stolen information sent ?

Search: `ip.addr == 10.4.10.132 && smtp`

`Follow > TCP stream`, we look at the **RCPT TO**

**Answer : sales.del@macwinlogistics.in**

### 23 - What is the password used by the malware to send the email ?

Search: `ip.addr == 10.4.10.132 && smtp`

`Follow > TCP flow`, we look at the exchange at the authentication level

```shell
echo U2FsZXNAMjM= | base64 -d
Sales@23
```

**Answer :Sales@23**

### 24 - Which malware variant exfiltrated the data ?

Search: `ip.addr == 10.4.10.132 && smtp`

`Follow > TCP stream`, we notice a large base64 block in the mail

```shell
echo SGF3a0V5ZSBLZXlsb2dnZXIgLSBSZWJvcm4gdjkgLSBQYXNzd29yZHMgTG9ncyAtIHJvbWFuLm1jZ3VpcmUgXCBCRUlKSU5HLTVDRDEtUEMgLSAxNzMuNjYuMTQ2LjExMg== | base64 -d
HawkEye Keylogger - Reborn v9 - Passwords Logs - roman.mcguire \ BEIJING-5CD1-PC - 173.66.146.112
```

**Answer : Reborn v9**

### 25 - What are the bankofamerica access credentials ? (username:password)

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

**Answer : roman.mcguire:P@ssw0rd$**

### 26 - Every how many minutes does the collected data get exfiltrated ?

Search: `ip.addr == 10.4.10.132 && smtp.req.command == "EHLO"`

We notice a request every 10min

**Answer : 10**
