# TeamSpy

## Info

- Category : Digital Forensics
- SHA1SUM : 1bc677daf51be254c8bfb9085f7375bbf1ee8e3b
- Published : June 4, 2022
- Author : Wyatt Roersma
- Size : 1.4G
- Tags : GrrCon Memory WIndows TeamViewer

Uncompress the challenge (pass: cyberdefenders.org)

### Scenario

An employee reported that his machine started to act strangely after receiving a suspicious email with a document file. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. Analyze the dumps and help the IR team figure out what happened!

### Tools

- Volatilty 2.6
- OSTviewer
- OfficeMalScanner
- VirusTotal
- dotnetfiddle

---

## Questions

### 1 - File->ecorpoffice / What is the PID the malicious file is running under?

We find the profile allowing to analyze the memory dump using volatility:

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem imageinfo
```

The image profile is `Win7SP1x64`. By using the `pslist` plugin, one can observe the different processes.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 pslist
```

`skypeC2autoup` looks suspicious. Its PID is **1364**

**Answer: 1364**


### 2 - File->ecorpoffice / What is the C2 server IP address?

We reuse **volatility** with the plugin **netsacn**

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 netscan
```

To see open ports and who is listening. `skypeC2autoup` established a connection with IP address **54.174.131.235**

**Answer: 54.174.131.235**

### 3 - File->ecorpoffice / What is the Teamviewer version abused by the malicious file?

We dump the memory of the process and we grep where it talks about the ip address

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 memdump -p 1364 -D ./output
```

```
strings -a10 -b10 1364.dmp | grep 54.174.131.235
```

We can see the version of `TeamViewer`.

**Answer: 0.2.2.2**

### 4 - File->ecorpoffice / What password did the malicious file use to enable remote access to the system?

For this question, we use the `editbox` plugin which allows you to see the elements displayed by the windows dialog boxes.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 editbox
```

In one of the dialog boxes, the password used to launch the process is displayed.

**Answer: P59fS93m**

### 5 - File->ecorpoffice / What was the sender's email address that delivered the phishing email?

You have to find the `Outlook` file containing the user's mailbox. Using the **filescan** plugin.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 filescan > output/out.txt
```

We retrieve the location of the PST file by doing:

```
cat output/out.txt | grep -i .pst
```

We have the memory address of the PST and we dump it with volatility

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007fd38c80 -D=output/
```

Open it in `OutlookForensicTool`.

**Answer: karenmiles@t-online.de**


### 6 - File->ecorpoffice / What is the MD5 hash of the malicious document?

In `OutlookForensicTool`, we download the file contained in the phishing email and calculate its hash.

**Answer: c2dbf24a0dc7276a71dd0824647535c9**

### 7 - File->ecorpoffice / What is the bitcoin wallet address that ransomware was demanded?

Look in the victim's other emails. One of the emails contains the bitcoin wallet address.

**Answer: 25UMDkGKBe484WSj5Qd8DhK6xkMUzQFydY**

### 8 - File->ecorpoffice / What is the ID given to the system by the malicious file for remote access?

We reuse `editbox` to see the parameters given to the malware.

```
vol.py -f win7ecorpoffice2010-36b02ed3.vmem --profile=Win7SP1x64 editbox
```


**Answer: 528 812 561**


### 9 - File->ecorpoffice / What is the IPv4 address the actor last connected to the system with the remote access tool?

We look at the ip addresses of the process then if they are close to the use of **TeamViewer**.

```
strings output/1364.dmp | grep -B 3 -A 2 -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep teamviewer -B 3 -A 3
```

**Answer: 31.6.13.155**


### 10 - File->ecorpoffice / What Public Function in the word document returns the full command string that is eventually run on the system?

We recover the Word document using OutlookForensicTool (in the mails that we previously put in).

The `OfficeMalScanner` tool is used to extract macros from Word documents. We can then analyze the macro using the site: `https://dotnetfiddle.net/`

**Answer: UsoJar**

### 11 - File->ecorpwin7 / What is the MD5 hash of the malicious document?

We do as in question **5**. We recover the mailbox that we analyze.

We see that the person receives a document called: `Important_ECORP_Lawsuit_Washington_Leak.rtf`

We suspect that it is this document that is suspect. However, it seems impossible to open it normally. It looks corrupt.

Many blocks of null bytes were added at the end of the document. You have to clean them and you get the hash of the new document.

**Answer: 00e4136876bf4c1069ab9c4fe40ed56f**

### 12 - File->ecorpwin7 / What is the common name of the malicious file that gets loaded?"

We list the orders placed to see if malicious things have been done:

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 cmdline
```

There are two commands that launch `test.dll` from a suspicious path. We retrieve their memory addresses using `filescan` and dump them.

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 filescan > output/out2.txt
```

```
cat output/out2.txt | grep -i test.dll
```

We dump them and upload them to VirusTotal which gives the answer.

**Answer: PlugX**


### 13 - File->ecorpwin7 / What password does the attacker use to stage the compressed file for exfil?

Here it is necessary to correlate several pieces of information to find what seems suspicious.

Using the **volatility** `cmdline` and `pslist` plugins, it is possible to see that the **conhost.exe** process can be spoofed. (Big PID and run from command line)

We then dump the memory of the process:

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 memdump -p 3056 -D output/
```

then we do a grep to see if it speaks of a password. The file is encoded in **little endian**. Then use the following command:

```
strings -el output/3056.dmp | grep password
```

**Answer: password1234**


### 14 - File->ecorpwin7 / What is the IP address of the c2 server for the malicious file?

We do a `netscan` to see if there are connections with a C2.

```
vol.py -f ecorpwin7-e73257c4.vmem --profile=Win7SP1x64 netscan
```

The `svchost.exe` process establishes connections with an external IP address

**Answer: 52.90.110.169**

### 15 - File->ecorpwin7 / What is the email address that sent the phishing email?

We look at the pst file that we recovered in question 11.

**Answer: lloydchung@allsafecybersec.com**


### 16 - File->ecorpwin7 / What is the name of the deb package the attacker staged to infect the E Coin Servers?

We check the children of `svchost.exe` using `pstree`;

we see that `rundll32.exe` has pid **2404** and is a child of `scvhost.exe`. We dump using `memdump` rundll32.exe

We look at the process to see if it has downloaded a linux package.

```
strings 2404.dmp | grep wget
```

**Answer: linuxav.deb**
