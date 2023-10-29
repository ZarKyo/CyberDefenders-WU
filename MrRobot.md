# MrRobot

## Info

- Category : Digital Forensics
- SHA1SUM :	b8dab80336c37688f276bfbfac0ac1681398a30d
- Published : May 18, 2022
- Author : Wyatt Roersma
- Size : 1.1 GB
- Tags : PHISHINGWINDOWSMEMORYRAT

### Scenario

An employee reported that his machine started to act strangely after receiving a suspicious email for a security update. The incident response team captured a couple of memory dumps from the suspected machines for further inspection. Analyze the dumps and help the IR team figure out what happened!

### Tools

- Volatility2
- Volatility3
- Rstudio

---

## Questions

### 1 - Machine:Target1 / What email address tricked the front desk employee into installing a security update?

We make a string on the memory image to see if we manage to see email adresses.

```
strings Target1.vmss | egrep '([[:alnum:]_.-]{1,64}+@[[:alnum:]_.-]{2,255}+?\.[[:alpha:].]{2,4})'
```

**Answer :  th3wh1t3r0s3@gmail.com**

### 2 - What is the filename that was delivered in the email?

Similarly but looking around the previously seen email address see the email that was received

```
strings Target1-1dd8701f.vmss | grep -i TH3WH1T3R0S3@GMAIL.COM -a5
```

**Answer : AnyConnectInstaller.exe**


### 3 - What is the name of the rat's family used by the attacker?

We retrieve the list of files loaded in memory

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 filescan > filescan.txt
```

We retrieve the memory address of the malware for the dump just after :

```
cat filescan.txt | grep AnyConnectInstaller.exe
```

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003ed57968 -D output/
```

We put the hash on virustotal

**Answer : XTREMERAT**

### 4 - The malware appears to be leveraging process injection. What is the PID of the process that is injected?

By putting the hash on VirusTotal, we see in the **Process Injected** category that it is injected into IE Explorer.

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 pslit
```

To list the processes and their PIDs

**Answer : 2996**

### 5 - What is the unique value the malware is using to maintain persistence after reboot?

VirusTotal gives the value of the run key used by the malware

**Answer : MrRobot**

### 6 - Malware often uses a unique value or name to ensure that only one copy runs on the system. What is the unique name the malware is using?

Mutants are used to know when a machine is infected or not

We can list the **handles** of the infected process and see if there are mutants

```
vol.py -f Target1.dmp --profile=Win7SP1x86_23418 handles -p 2996 | grep -i mutant
```

**Answer : fsociety0.dat**

### 7 - It appears that a notorious hacker compromised this box before our current attackers. Name the movie he or she is from.

Rather particular question but by looking at the list of users present on the machine we can find the name of the film:

```
vol.py -f Target1.dmp --profile=Win7SP1x86_23418 cachedump
```

One of the users is called **zerocool** like in the movie :

**Answer : hackers**

### 8 - Machine:Target1 / What is the NTLM password hash for the administrator account?

We use the `hashdump` plugin to retrieve hashes from the memory dump

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 hashdump
```

**Answer : 79402b7671c317877b8b954b3311fa82**

### 9 - The attackers appear to have moved over some tools to the compromised front desk host. How many tools did the attacker move?

We use the plugin `consoles` of volatility to see the history of orders placed

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 consoles
```

You can see the list of suspicious executables in the **Tmp** folder.

**Answer : 3**

### 10 - What is the password for the front desk local administrator account?

Same

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 consoles
```

the wce tool was used and shows the mdp.

**Answer : flagadmin@1234**

### 11 -  What is the std create data timestamp for the nbtscan.exe tool?

We recover the MFT of the memory image which is the list of files with their dates of modification + creation

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 mftparser > mft.txt
```

```
cat mft.txt | grep nbtscan.exe
```

**Answer : 2015-10-09 10:45:12 UTC**

### 12 - The attackers appear to have stored the output from the nbtscan.exe tool in a text file on a disk called nbs.txt. What is the IP address of the first machine in that file?

We retrieve the file using volatility :

```
cat filescan.txt | grep nbs.txt
```
```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003fdb7808 -D output/
```
```
cat output/file.None.0x83eda598.dat
```

**Answer : 10.1.1.2**

### 13 - What is the full IP address and the port was the attacker's malware using?

We list the connections made by the machine

```
vol.py -f Target1-1dd8701f.vmss --profile=Win7SP1x86_23418 netscan
```

**Answer : 180.76.254.120:22**

### 14 - It appears the attacker also installed legit remote administration software. What is the name of the running process?

By listing the different processes using the `pslist` plugin, we see a well-known software

**Answer : TeamViewer.exe**

### 15 - It appears the attackers also used a built-in remote access method. What IP address did they connect to?

By reusing the `netscan` plugin we can see the connections

**Answer : 10.1.1.21** 

### 16 - Machine:Target2 / It appears the attacker moved latterly from the front desk machine to the security admins (Gideon) machine and dumped the passwords. What is Gideon's password?

Using the `consoles` plugin we see the history:

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

the wce utility wrote its output to the `w.tmp` file. We dump it

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 filescan > filescan.txt
```
```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003fcf2798 -D output/
```
```
cat output/file.None.0x85a35da0.dat
```

And we recover the password

**Answer : t76fRJhS**

### 17 - Once the attacker gained access to "Gideon," they pivoted to the AllSafeCyberSec domain controller to steal files. It appears they were successful. What password did they use?

We look at the command history and we see the password used

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

**Answer : 123qwe!@#** 

### 18 - What was the name of the RAR file created by the attackers?

Same thing, look at the command history :

```
vol.py -f target2-6186fe9f.vmss --profile=Win7SP1x86_23418 consoles
```

**Answer : crownjewlez.rar**

### 19 - How many files did the attacker add to the RAR archive?

We look at the pid of the process that connected to the DC (conhost)

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

**Answer : 3**

### 20 - The attacker appears to have created a scheduled task on Gideon's machine. What is the name of the file associated with the scheduled task?

We list the scheduled tasks

```
cat filescan.txt | grep -i “System32\\\tasks\\\\”
```

One of the spots looks suspicious: **At1**

We dump it and cat the file.

**Answer : 1.bat**

### 22 - Machine:POS / What is the malware CNC's server?

We look at the connections of the machine to the outside :

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86_23418 netscan
```

**Answer : 54.84.237.92**

### 23 - What is the common name of the malware used to infect the POS system?

We use the volatility plugin `malfind` to see if it finds anything :

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86_23418 malfind -p 3208 -D output/
```

On récupère le malware du processus infecté puis VirusTotal

**Answer : Dexter**

### 23 - In the POS malware whitelist. What application was specific to Allsafecybersec?

We dump the dlls used at the memory address of the malicious process

```
vol.py -f POS-01-c4e8f786.vmss --profile=Win7SP1x86 dlldump -p 3208 --base=0x50000 -D ./
```

We look at its character strings.

```
strings module.3208.3fd324d8.50000.dll | grep -i exe"  
```

**Answer : allsafe_protector.exe**

### 24 - What is the name of the file the malware was initially launched from?

Using the `iehistory` plugin we can see which executable answers the question

**Answer : allsafe_update.exe**
