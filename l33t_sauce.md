# l337 S4uc3

## Info

- Category : Digital Forensics, Incident response 
- SHA1SUM :	94ac99ef544086f0be9f5f6b00ae1a0834b0027b
- Published : Nov. 16, 2021
- Author :	Wyatt Roersma
- Size : 117 MB
- Tags : Wireshark PCAP Memory Network 

Uncompress the challenge (pass: cyberdefenders.org)

### Scenario

Everyone has heard of targeted attacks. Detecting these can be challenging, responding to these can be even more challenging. This scenario will test your network and host-based analysis skills to figure out the who, what, where, when, and how of this incident. There is sure to be something for all skill levels and the only thing you need to solve the challenge is some l337 S4uc3!

### Tools

- Volatility
- Wireshark
- Networkminer
- Brimsecurity

---

## Questions

### 1 - PCAP: Development.wse.local is a critical asset for the Wayne and Stark Enterprises, where the company stores new top-secret designs on weapons. Jon Smith has access to the website and we believe it may have been compromised, according to the IDS alert we received earlier today. First, determine the Public IP Address of the webserver?

We open the pcapng using **BrimSecurity**. We filter on HTTP requests.

We can see the IP 172.16.0.1 which communicates with the 172.16.0.108 to access the development.wse.local site.

In the response of the Host we can see the public IP of this site.

**Answer : 74.204.41.73**

### 2 - PCAP: Alright, now we need you to determine a starting point for the timeline that will be useful in mapping out the incident. Please determine the arrival time of frame 1 in the "GrrCON.pcapng" evidence file.

We open the pcapng in Wireshark.

In `Statistics > Capture file properties`

We have the Timestamp of the first packet to arrive. We convert it to UTC.

**Answer : 22:51:07 UTC**

### 3 - PCAP: What version number of PHP is the development.wse.local server running?

We open the pcapng in Wireshark.

We use the `ip.addr == 172.16.0.108 && http` filter. Because we know that the IP address of the site is this one.

We follow one of the HTTP flows and we find the version of PHP in the XPowered field.

**Answer : 5.3.2**

### 4 - PCAP: What version number of Apache is the development.wse.local web server using?

We open the pcapng in Wireshark.

We use the `ip.addr == 172.16.0.108 && http` filter. Because we know that the IP address of the site is this one.

We follow one of the HTTP streams and we find the apache version in the Server field.
 
**Answer: 2.2.14**

### 5 - IR: What is the common name of the malware reported by the IDS alert provided?

We open the image of the IDS alert. You can see the name of the alert at the top.

**Answer : zeus**

### 6 - PCAP: Please identify the Gateway IP address of the LAN because the infrastructure team reported a potential problem with the IDS server that could have corrupted the PCAP

We open the pcapng in Wireshark.

You can see a lot of **ARP** + **Ping** requests from `172.16.0.1` to other addresses in that subnet.

We suspect then that it is the Gateway.

**Answer: 172.16.0.1**

### 7 - IR: According to the IDS alert, the Zeus bot attempted to ping an external website to verify connectivity. What was the IP address of the website pinged?

We open the image of the IDS alert. We can see between which addresses there was an alert. The destination server is the Answer.

**Answer: 74.125.225.112**

### 8 - PCAP: It�s critical to the infrastructure team to identify the Zeus Bot CNC server IP address so they can block communication in the firewall as soon as possible. Please provide the IP address?

We open the pcapng in Brim.

We do the following research:

```
event_type=="alert" | count() by alert.severity,alert.signature | spell count
```

We have an alert called: `ET MALWARE Zbot POST Request to C2`

We do a search with this value we see the IP address that communicates with our machine.

**Answer : 88.198.6.20**

### 9 - PCAP: The infrastructure team also requests that you identify the filename of the �.bin� configuration file that the Zeus bot downloaded right after the infection. Please provide the file name?

We open the pcapng in Wireshark.

We do the following search:

```
ip.addr==88.198.6.20 && http
```

We see that there are downloads of several files including a .bin

**Answer: cf.bin**

### 10 - PCAP: No other users accessed the development.wse.local WordPress site during the timeline of the incident and the reports indicate that an account successfully logged in from the external interface. Please provide the password they used to log in to the WordPress page around 6:59 PM EST?

We open the pcapng in Wireshark.

We do the following research:

```
ip.addr==172.16.0.108 && http
```

In the different queries we look for one that corresponds to a login page. When we find it we follow the HTTP flow.

In stream 170 we see `log=Jsmith&pwd=wM812ugu` being sent.

**Answer : wM812ugu**

### 11 - PCAP: After reporting that the WordPress page was indeed accessed from an external connection, your boss comes to you in a rage over the potential loss of confidential top-secret documents. He calms down enough to admit that the design's page has a separate access code outside to ensure the security of their information. Before storming off he provided the password to the designs page �1qBeJ2Az� and told you to find a timestamp of the access time or you will be fired. Please provide the time of the accessed Designs page?

We analyze the pcap in NetworkMiner

We go to the `Credentials` tab and look at what time the given password was used: **1qBeJ2Az**

**Answer: 23:04:04 UTC**

### 12 - PCAP: What is the source port number in the shellcode exploit? Dest Port was 31708 IDS Signature GPL SHELLCODE x86 inc ebx NOOP

We open the pcapng in Wireshark.

We do the following research:

```
udp.port == 31708
```

(this destination port does not appear with the tcp protocol)

**Réponse : 39709**

### 13 - PCAP: What was the Linux kernel version returned from the meterpreter sysinfo command run by the attacker?

We open the pcapng in Wireshark.

We do a search using `Find a package`. Do a `sysinfo` search in the package detail.

We follow the TCP stream of the found packet and we find our Answer.

**Answer: 2.6.32-38-server**

### 14 - PCAP: What is the value of the token passed in frame 3897?

We open the pcapng in Wireshark.

We go to the package with the right number. We develop it and in the **HTML Form URL Encoded** category we find the token.

**Answer: b7aad621db97d56771d6316a6d0b71e9**

### 15 - PCAP: What was the tool that was used to download a compressed file from the webserver?

We open the pcapng in Brim.

we do the research to see the different user agents used.

```
_path=="http" | count() by user_agent
```

We check that the user agent **wget** downloads an archive


**Answer: Wget**

### 16 - PCAP: What is the download file name the user launched the Zeus bot?

In Wireshark:

```
ip.addr == 88.198.6.20 && http
```

We can see in the requests the download of an .exe

**Answer: bt.exe**

### 17 - Memory: What is the full file path of the system shell spawned through the attacker's meterpreter session?

We add the .zip in the right folder to have the right profile of the memory image.

here

```
sudo cp DFIRwebsvr.zip /usr/local/python2.7/dist-packages/volatility/plugins/overlays/linux/
```

You can run the following command to see the shells launched:

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_psaux
```

We then see the system shell launched

**Answer : /bin/sh**

### 18 - Memory: What is the Parent Process ID of the two 'sh' sessions?

We do :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pstree
```

We see that the shells are launched by an apache2.

**Answer: 1042**

### 19 - Memory: What is the latency_record_count for PID 1274?

We do :

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pslist
```

This recovers the malicious shell process offset: **0xffff880006dd8000**


```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_volshell
```

and we run `dt("task_struct",0xffff880006dd8000)`. For information on the process.

**Answer: 0**

### 20 - Memory: For the PID 1274, what is the first mapped file path?

We launch:

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_proc_maps
```

We look at PID 1274 and the first one is.

**Answer: /bin/dash**

### 21 - Memory:What is the md5hash of the receive.1105.3 file out of the per-process packet queue?

We launch:

```
vol.py -f webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pkt_queues -D output/
```

and we do:

```
md5sum output/receive.1105.3
```

**Answer : 184c8748cfcfe8c0e24d7d80cac6e9bd**
