# Brave

## Info 

- Category : Digital Forensics
- SHA1SUM : fa02a505471aeb89172f89cb27dd4e2eea14bb9e
- Published : June 20, 2021
- Author : DFIRScience
- Size : 1.2 GB
- Tags : Volatility Memory Brave Winows
 	
Unzip the challenge (pass: cyberdefenders.org)

### Scenario

A memory image was taken from a seized Windows machine. Analyze the image and answer the provided questions.

### Tools

- Volatility 3
- CertUtil
- HxD

---

##	Questions

### 1 - What time was the RAM image acquired according to the suspect system ? (YYYY-MM-DD HH:MM:SS)

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.info
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
Variable	Value

Kernel Base	0xf8043cc00000
DTB	0x1aa000
Symbols	file:///usr/local/lib/python3.8/dist-packages/volatility3-2.0.0-py3.8.egg/volatility3/symbols/windows/ntkrnlmp.pdb/769C521E4833ECF72E21F02BF33691A5-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf8043d80f368
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	4
SystemTime	2021-04-30 17:52:19
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Tue Oct 11 07:04:26 1977
```

**Réponse : 2021-04-30 17:52:19**	

### 2 - What is the SHA256 hash value of the RAM image ?

```shell
sha256sum 20210430-Win10Home-20H2-64bit-memdump.mem
9db01b1e7b19a3b2113bfb65e860fffd7a1630bdf2b18613d206ebf2aa0ea172  20210430-Win10Home-20H2-64bit-memdump.mem
```

**Réponse : 9db01b1e7b19a3b2113bfb65e860fffd7a1630bdf2b18613d206ebf2aa0ea172**

### 3 - What is the process ID of "brave.exe" ?

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.pstree
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime
[...]
4856	1872	brave.exe	0xbf0f6ca782c0	0	-	1	False	2021-04-30 17:48:45.000000 	2021-04-30 17:50:56.000000 
```

**Réponse : 4856**

### 4 - How many established network connections were there at the time of acquisition ? (number)

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.netscan | grep ESTABLISHED | wc -l
10
```

**Réponse : 10**

### 5 - What FQDN does Chrome have an established network connection with ?

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.netscan | grep ESTABLISHED
0xbf0f6a53ca20.0TCPv4	10.0.2.15DB scan49833fin52.230.222.68   443     ESTABLISHED	2812	svchost.exe	2021-04-30 17:50:07.000000 
0xbf0f6ad16050	TCPv4	10.0.2.15	49829	142.250.191.208	443	ESTABLISHED	5624	svchost.exe	2021-04-30 17:49:58.000000 
0xbf0f6ad1fad0	TCPv4	10.0.2.15	49847	52.230.222.68	443	ESTABLISHED	2812	svchost.exe	2021-04-30 17:52:17.000000 
0xbf0f6c6352b0	TCPv4	10.0.2.15	49842	52.113.196.254	443	ESTABLISHED	5104	SearchApp.exe	2021-04-30 17:51:25.000000 
0xbf0f6c7104d0	TCPv4	10.0.2.15	49778	185.70.41.130	443	ESTABLISHED	1840	chrome.exe	2021-04-30 17:45:00.000000 
0xbf0f6cd4fa20	TCPv4	10.0.2.15	49837	204.79.197.200	443	ESTABLISHED	5104	SearchApp.exe	2021-04-30 17:51:18.000000 
0xbf0f6d0c64a0	TCPv4	10.0.2.15	49843	204.79.197.222	443	ESTABLISHED	5104	SearchApp.exe	2021-04-30 17:51:26.000000 
0xbf0f6d51c4a0	TCPv4	10.0.2.15	49838	13.107.3.254	443	ESTABLISHED	5104	SearchApp.exe	2021-04-30 17:51:23.000000 
0xbf0f6d525a20	TCPv4	10.0.2.15	49845	23.101.202.202	443	ESTABLISHED	1156	MsMpEng.exe	2021-04-30 17:51:36.000000 
0xe80000193a20	TCPv4	10.0.2.15	49845	23.101.202.202	443	ESTABLISHED	1156	MsMpEng.exe	2021-04-30 17:51:36.000000 
```

On remarque que Chrome a établis une connexion avev l'IP **185.70.41.130**, on fait donc un lookup sur cette IP.

**Réponse : protonmail.ch**

### 6 - What is the MD5 hash value of process memory for PID 6988 ?

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist --pid 6988 --dump
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

6988	4352	OneDrive.exe	0xbf0f6d4262c0	26	-	1	True	2021-04-30 17:40:01.000000 	N/A	pid.6988.0x1c0000.dmp
```

```shell
sudo md5sum pid.6988.0x1c0000.dmp 
0b493d8e26f03ccd2060e0be85f430af  pid.6988.0x1c0000.dmp
```

**Réponse : 0b493d8e26f03ccd2060e0be85f430af**

### 7 - What is the word starting at offset 0x45BE876 with a length of 6 bytes ?

Avec Ghex, on ouvre le fichier mémoire et on va à l'offset 0x45BE876 `Edit > Goto Byte > 0x45BE876`

2 caractères hexadécimal = 1 octet (bytes en anglais). On prend donc les 6 premiers couples de caratères hexadécimal ce qui donne **hacker**

**Réponse : hacker**

### 8 - What is the creation date and time of the parent process of "powershell.exe" ? (YYYY-MM-DD HH:MM:SS)

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.pstree | grep -i -B 5 powershell.exe > pstree_powsershell.txt

cat pstree_powsershell.txt 
* 892	668	fontdrvhost.ex	0xbf0f6b7091c0	5	-	1	False	2021-04-30 12:39:44.000000 	N/A
* 564	668	LogonUI.exe	0xbf0f6b7b7100	0	-	1	False	2021-04-30 12:39:44.000000 	2021-04-30 17:39:58.000000 
* 4296	668	userinit.exe	0xbf0f6ca8f080	0	-	1	False	2021-04-30 17:39:48.000000 	2021-04-30 17:40:12.000000 
** 4352	4296	explorer.exe	0xbf0f6ca662c0	82	-	1	False	2021-04-30 17:39:48.000000 	N/A
*** 6884	4352	VBoxTray.exe	0xbf0f6d186080	11	-	1	False	2021-04-30 17:40:01.000000 	N/A
*** 5096	4352	powershell.exe	0xbf0f6d97f2c0	12	-	1	False	2021-04-30 17:51:19.000000 	N/A
```

**Réponse : 2021-04-30 17:39:48**

### 9 - What is the full path and name of the last file opened in notepad ?

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.cmdline | grep notepad > notepad.txt

cat notepad.txt 
2520	notepad.exe	"C:\Windows\system32\NOTEPAD.EXE" C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum
```

**Réponse : C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum**

### 10 - How long did the suspect use Brave browser ? (hh:mm:ss)

```shell
sudo vol -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.registry.userassist > userassist.log 

cat userassist.log | grep -i brave
Hive Offset	Hive Name	Path	Last Write Time	Type	Name	ID	Count	Focus Count	Time Focused	Last Updated	Raw Data
[...]
* 0xa80333cda000	\??\C:\Users\John Doe\ntuser.dat	ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count	2021-04-30 17:52:18.000000 	Value	%ProgramFiles%\BraveSoftware\Temp\GUM20E0.tmp\BraveUpdate.exe	N/A	0	0	0:00:03.531000	N/A	
* 0xa80333cda000	\??\C:\Users\John Doe\ntuser.dat	ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count	2021-04-30 17:52:18.000000 	Value	%ProgramFiles%\BraveSoftware\Update\BraveUpdate.exe	N/A	0	1	0:00:24.797000	N/A	
* 0xa80333cda000	\??\C:\Users\John Doe\ntuser.dat	ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count	2021-04-30 17:52:18.000000 	Value	Brave	N/A	9	22	4:01:54.328000	2021-04-30 17:48:45.000000 	
* 0xa80333cda000	\??\C:\Users\John Doe\ntuser.dat	ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count	2021-04-30 17:51:18.000000 	Value	C:\Users\Public\Desktop\Brave.lnk	N/A	8	0	0:00:00.508000	2021-04-30 17:48:45.000000
```

**Réponse : 4:01:54**