# DumpMe

## Info 

Category : 	Digital Forensics

SHA1SUM :	70f1bafca632f7518cb0a0ee126246b040247b37

Published :	May 30, 2021

Author :	Champlain College

Size :		1.2 GB

Tags :		Volatility DFIR Windows Memory 


Scenario :

One of the SOC analysts took a memory dump from a machine infected with a meterpreter malware. As a Digital Forensicators, your job is to analyze the dump, extract the available indicators of compromise (IOCs) and answer the provided questions.

Tools :

- Volatility 2
- sha1sum


## Question

#### 1 - What is the SHA1 hash of Triage-Memory.mem (memory dump) ?

```shell
sha1sum Triage-Memory.mem 
c95e8cc8c946f95a109ea8e47a6800de10a27abd  Triage-Memory.mem
```

**Réponse : c95e8cc8c946f95a109ea8e47a6800de10a27abd**

#### 2 - What volatility profile is the most appropriate for this machine ? (ex: Win10x86_14393)

```shell
vol.py -f Triage-Memory.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/remnux/Documents/DumpMe/Triage-Memory.mem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029f80a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800029f9d00L
                KPCR for CPU 1 : 0xfffff880009ee000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-03-22 05:46:00 UTC+0000
     Image local date and time : 2019-03-22 01:46:00 -0400
```

**Réponse : Win7SP1x64**

#### 3 - What was the process ID of notepad.exe ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 pstree
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8003de39c0:explorer.exe                     1432   1308     28    976 2019-03-22 05:32:07 UTC+0000
. 0xfffffa80042aa430:cmd.exe                         1408   1432      1     23 2019-03-22 05:34:12 UTC+0000
. 0xfffffa8005d067d0:StikyNot.exe                    1628   1432      8    183 2019-03-22 05:34:42 UTC+0000
. 0xfffffa80042dbb30:chrome.exe                      3248   1432     32    841 2019-03-22 05:35:14 UTC+0000
.. 0xfffffa8005442b30:chrome.exe                     4232   3248     14    233 2019-03-22 05:35:17 UTC+0000
.. 0xfffffa80047beb30:chrome.exe                     3244   3248      7     91 2019-03-22 05:35:15 UTC+0000
.. 0xfffffa80053306f0:chrome.exe                     1816   3248     14    328 2019-03-22 05:35:16 UTC+0000
.. 0xfffffa8005300b30:chrome.exe                     4156   3248     14    216 2019-03-22 05:35:17 UTC+0000
.. 0xfffffa8005419b30:chrome.exe                     4240   3248     14    215 2019-03-22 05:35:17 UTC+0000
.. 0xfffffa800540db30:chrome.exe                     4520   3248     10    234 2019-03-22 05:35:18 UTC+0000
.. 0xfffffa80052f0060:chrome.exe                     2100   3248      2     59 2019-03-22 05:35:15 UTC+0000
.. 0xfffffa80053cbb30:chrome.exe                     4688   3248     13    168 2019-03-22 05:35:19 UTC+0000
. 0xfffffa800474c060:OUTLOOK.EXE                     3688   1432     30   2023 2019-03-22 05:34:37 UTC+0000
. 0xfffffa8004798320:calc.exe                        3548   1432      3     77 2019-03-22 05:34:43 UTC+0000
. 0xfffffa80053d3060:POWERPNT.EXE                    4048   1432     23    765 2019-03-22 05:35:09 UTC+0000
. 0xfffffa8004905620:hfs.exe                         3952   1432      6    214 2019-03-22 05:34:51 UTC+0000
.. 0xfffffa8005a80060:wscript.exe                    5116   3952      8    312 2019-03-22 05:35:32 UTC+0000
... 0xfffffa8005a1d9e0:UWkpjFjDzM.exe                3496   5116      5    109 2019-03-22 05:35:33 UTC+0000
.... 0xfffffa8005bb0060:cmd.exe                      4660   3496      1     33 2019-03-22 05:35:36 UTC+0000
. 0xfffffa80054f9060:notepad.exe                     3032   1432      1     60 2019-03-22 05:32:22 UTC+0000
. 0xfffffa8005b49890:vmtoolsd.exe                    1828   1432      6    144 2019-03-22 05:32:10 UTC+0000
. 0xfffffa800474fb30:taskmgr.exe                     3792   1432      6    134 2019-03-22 05:34:38 UTC+0000
. 0xfffffa80053f83e0:EXCEL.EXE                       1272   1432     21    789 2019-03-22 05:33:49 UTC+0000
. 0xfffffa8004083880:FTK Imager.exe                  3192   1432      6    353 2019-03-22 05:35:12 UTC+0000
 0xfffffa8003c72b30:System                              4      0     87    547 2019-03-22 05:31:55 UTC+0000
. 0xfffffa8004616040:smss.exe                         252      4      2     30 2019-03-22 05:31:55 UTC+0000
 0xfffffa80050546b0:csrss.exe                         332    324     10    516 2019-03-22 05:31:58 UTC+0000
 0xfffffa8005259060:wininit.exe                       380    324      3     78 2019-03-22 05:31:58 UTC+0000
. 0xfffffa8005680910:services.exe                     476    380     12    224 2019-03-22 05:31:59 UTC+0000
.. 0xfffffa8005409060:dllhost.exe                    2072    476     13    194 2019-03-22 05:32:14 UTC+0000
.. 0xfffffa80055b0060:wmpnetwk.exe                   2628    476      9    210 2019-03-22 05:32:18 UTC+0000
.. 0xfffffa800583db30:svchost.exe                    1028    476     19    307 2019-03-22 05:32:05 UTC+0000
.. 0xfffffa8005775b30:svchost.exe                     796    476     15    368 2019-03-22 05:32:03 UTC+0000
... 0xfffffa80059e6890:dwm.exe                       1344    796      3     88 2019-03-22 05:32:07 UTC+0000
.. 0xfffffa8005508650:SearchIndexer.                 2456    476     13    766 2019-03-22 05:32:17 UTC+0000
.. 0xfffffa80057beb30:svchost.exe                     932    476     10    568 2019-03-22 05:32:03 UTC+0000
.. 0xfffffa800432f060:svchost.exe                    3300    476     13    346 2019-03-22 05:34:15 UTC+0000
.. 0xfffffa8005478060:msdtc.exe                      2188    476     12    146 2019-03-22 05:32:15 UTC+0000
.. 0xfffffa800577db30:svchost.exe                     820    476     33   1073 2019-03-22 05:32:03 UTC+0000
... 0xfffffa80059cc620:taskeng.exe                   1292    820      4     83 2019-03-22 05:32:07 UTC+0000
... 0xfffffa8004300620:taskeng.exe                   1156    820      4     93 2019-03-22 05:34:14 UTC+0000
.. 0xfffffa80059cb7c0:taskhost.exe                   1276    476      8    183 2019-03-22 05:32:07 UTC+0000
.. 0xfffffa8005b4eb30:vmtoolsd.exe                   1852    476     10    314 2019-03-22 05:32:11 UTC+0000
.. 0xfffffa800570d060:svchost.exe                     672    476      7    341 2019-03-22 05:32:02 UTC+0000
.. 0xfffffa8005a324e0:FileZilla Serv                 1476    476      9     81 2019-03-22 05:32:07 UTC+0000
.. 0xfffffa8005c4ab30:svchost.exe                    2888    476     11    152 2019-03-22 05:32:20 UTC+0000
.. 0xfffffa8005ba0620:ManagementAgen                 1932    476     10    102 2019-03-22 05:32:11 UTC+0000
.. 0xfffffa80056e1060:svchost.exe                     592    476      9    375 2019-03-22 05:32:01 UTC+0000
... 0xfffffa80054d2380:WmiPrvSE.exe                  2196    592     11    222 2019-03-22 05:32:15 UTC+0000
... 0xfffffa8005c8e440:WmiPrvSE.exe                  2436    592      9    245 2019-03-22 05:32:33 UTC+0000
... 0xfffffa80047cb060:iexplore.exe                  3576    592     12    403 2019-03-22 05:34:48 UTC+0000
.... 0xfffffa80047e9540:iexplore.exe                 2780   3576      6    233 2019-03-22 05:34:48 UTC+0000
.. 0xfffffa8005850a30:spoolsv.exe                     864    476     12    279 2019-03-22 05:32:04 UTC+0000
.. 0xfffffa80057e4560:svchost.exe                     232    476     15    410 2019-03-22 05:32:03 UTC+0000
.. 0xfffffa80058ed390:OfficeClickToR                 1136    476     23    631 2019-03-22 05:32:05 UTC+0000
.. 0xfffffa8005af24e0:VGAuthService.                 1768    476      3     89 2019-03-22 05:32:09 UTC+0000
.. 0xfffffa8004330b30:sppsvc.exe                     3260    476      4    149 2019-03-22 05:34:15 UTC+0000
.. 0xfffffa800575e5b0:svchost.exe                     764    476     20    447 2019-03-22 05:32:02 UTC+0000
. 0xfffffa80056885e0:lsass.exe                        484    380      7    650 2019-03-22 05:32:00 UTC+0000
. 0xfffffa8005696b30:lsm.exe                          492    380     10    155 2019-03-22 05:32:00 UTC+0000
 0xfffffa8005268b30:winlogon.exe                      416    364      3    110 2019-03-22 05:31:58 UTC+0000
 0xfffffa800525a9e0:csrss.exe                         372    364     11    557 2019-03-22 05:31:58 UTC+0000
. 0xfffffa80042ab620:conhost.exe                     1008    372      2     55 2019-03-22 05:34:12 UTC+0000
. 0xfffffa8005c1ab30:conhost.exe                     4656    372      2     49 2019-03-22 05:35:36 UTC+0000
 0xfffffa8005be12c0:FileZilla Serv                   1996   1860      3     99 2019-03-22 05:32:12 UTC+0000
```

**Réponse : 3032**

#### 4 - Name the child process of wscript.exe.

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 pstree
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8003de39c0:explorer.exe                     1432   1308     28    976 2019-03-22 05:32:07 UTC+0000
. 0xfffffa80042aa430:cmd.exe                         1408   1432      1     23 2019-03-22 05:34:12 UTC+0000
[...]
. 0xfffffa800474c060:OUTLOOK.EXE                     3688   1432     30   2023 2019-03-22 05:34:37 UTC+0000
. 0xfffffa8004798320:calc.exe                        3548   1432      3     77 2019-03-22 05:34:43 UTC+0000
. 0xfffffa80053d3060:POWERPNT.EXE                    4048   1432     23    765 2019-03-22 05:35:09 UTC+0000
. 0xfffffa8004905620:hfs.exe                         3952   1432      6    214 2019-03-22 05:34:51 UTC+0000
.. 0xfffffa8005a80060:wscript.exe                    5116   3952      8    312 2019-03-22 05:35:32 UTC+0000
... 0xfffffa8005a1d9e0:UWkpjFjDzM.exe                3496   5116      5    109 2019-03-22 05:35:33 UTC+0000
.... 0xfffffa8005bb0060:cmd.exe                      4660   3496      1     33 2019-03-22 05:35:36 UTC+0000
. 0xfffffa80054f9060:notepad.exe                     3032   1432      1     60 2019-03-22 05:32:22 UTC+0000
[...]
```

**Réponse : UWkpjFjDzM.exe**

#### 5 - What was the IP address of the machine at the time the RAM dump was created ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 netscan
Volatility Foundation Volatility Framework 2.6.1

Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x13e057300        UDPv4    10.0.0.101:55736               *:*                                   2888     svchost.exe    2019-03-22 05:32:20 UTC+0000
[...]
```

**Réponse : 10.0.0.101**

#### 6 - Based on the answer regarding the infected PID, can you determine the IP of the attacker ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 netscan | grep UWkpjFjDzM.exe
Volatility Foundation Volatility Framework 2.6.1

0x13e397190        TCPv4    10.0.0.101:49217               10.0.0.106:4444      ESTABLISHED      3496     UWkpjFjDzM.exe 
```

**Réponse : 10.0.0.106**

#### 7 - How many processes are associated with VCRUNTIME140.dll ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 dlllist | grep -i VCRUNTIME140.dll | wc -l
Volatility Foundation Volatility Framework 2.6.1

5
```

**Réponse : 5**

#### 8 - After dumping the infected process, what is its md5 hash ?
	
```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 procdump -p 3496 -D .
Volatility Foundation Volatility Framework 2.6.1

Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa8005a1d9e0 0x0000000000400000 UWkpjFjDzM.exe       OK: executable.3496.exe
```

```shell
md5sum executable.3496.exe 
690ea20bc3bdfb328e23005d9a80c290  executable.3496.exe
```

**Réponse : 690ea20bc3bdfb328e23005d9a80c290**

#### 9 - What is the LM hash of Bob's account ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 hashdump
Volatility Foundation Volatility Framework 2.6.1

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Bob:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**Réponse : aad3b435b51404eeaad3b435b51404ee**

#### 10 - What memory protection constants does the VAD node at 0xfffffa800577ba10 have ?

VAD = Virtual address descriptors

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 vadinfo | grep -i -A5 0xfffffa800577ba10
Volatility Foundation Volatility Framework 2.6.1

VAD node @ 0xfffffa800577ba10 Start 0x0000000000030000 End 0x0000000000033fff Tag Vad 
Flags: NoChange: 1, Protection: 1
Protection: PAGE_READONLY
Vad Type: VadNone
ControlArea @fffffa8005687a50 Segment fffff8a000c4f870
NumberOfSectionReferences:          1 NumberOfPfnReferences:           0
```

**Réponse : PAGE_READONLY**

#### 11 - What memory protection did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 vadinfo | grep -i -A5 "0x00000000033c0000 end 0x00000000033dffff"
Volatility Foundation Volatility Framework 2.6.1

VAD node @ 0xfffffa80052652b0 Start 0x00000000033c0000 End 0x00000000033dffff Tag VadS
Flags: CommitCharge: 32, PrivateMemory: 1, Protection: 24
Protection: PAGE_NOACCESS
Vad Type: VadNone
```

**Réponse : PAGE_NOACCES**

#### 12 - There was a VBS script that ran on the machine. What is the name of the script ? (submit without file extension)

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 cmdline | grep .vbs
Volatility Foundation Volatility Framework 2.6.1

Command line : "C:\Windows\System32\wscript.exe" //B //NOLOGO %TEMP%\vhjReUDEuumrX.vbs
```

**Réponse : vhjReUDEuumrX**

#### 13 - An application was run at 2019-03-07 23:06:58 UTC. What is the name of the program ? (Include extension)
	
```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 shimcache | grep "2019-03-07 23:06:58 UTC"
Volatility Foundation Volatility Framework 2.6.1


2019-03-07 23:06:58 UTC+0000   \??\C:\Program Files (x86)\Microsoft\Skype for Desktop\Skype.exe
```

**Réponse : Skype.exe**

#### 14 - What was written in notepad.exe at the time when the memory dump was captured ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 memdump -p 3032 -D .
Volatility Foundation Volatility Framework 2.6.1

************************************************************************
Writing notepad.exe [  3032] to 3032.dmp
```

```shell
strings -el 3032.dmp | grep "flag<"
flag<REDBULL_IS_LIFE>
```

**Réponse : flag<REDBULL_IS_LIFE>**

#### 15 - What is the short name of the file at file record 59045 ?

```shell
vol.py -f Triage-Memory.mem --profile=Win7SP1x64 mftparser | grep -A15 -B10 "59045"
Volatility Foundation Volatility Framework 2.6.1

2019-03-21 17:11:21 UTC+0000 2019-03-21 17:11:21 UTC+0000   2019-03-21 17:11:21 UTC+0000   2019-03-21 17:11:21 UTC+0000   Users\Bob\AppData\Local\Google\Chrome\USERDA~1\CERTIF~2\1067\_PLATF~1\all\sths\A577AC~1.STH

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-03-21 17:11:21 UTC+0000 2019-03-21 17:11:21 UTC+0000   2019-03-21 17:11:21 UTC+0000   2019-03-21 17:11:21 UTC+0000   Users\Bob\AppData\Local\Google\Chrome\USERDA~1\CERTIF~2\1067\_PLATF~1\all\sths\a577ac9ced7548dd8f025b67a241089df86e0f476ec203c2ecbedb185f282638.sth

$DATA
0000000000: 7b 22 74 72 65 65 5f 73 69 7a 65 22 3a 35 33 30   {"tree_size":530
0000000010: 35 30 2c 22 74 69 6d 65 73 74 61 6d 70 22 3a 31   50,"timestamp":1
0000000020: 35 35 33 31 36 30 39 35 39 30 34 35 2c 22 73 68   553160959045,"sh
0000000030: 61 32 35 36 5f 72 6f 6f 74 5f 68 61 73 68 22 3a   a256_root_hash":
0000000040: 22 53 33 42 2f 45 6f 55 38 4a 33 76 57 61 56 6d   "S3B/EoU8J3vWaVm
0000000050: 51 61 36 30 2b 47 53 62 67 67 4c 70 46 68 49 47   Qa60+GSbggLpFhIG
0000000060: 38 7a 36 6c 6f 56 79 49 35 39 53 30 3d 22 2c 22   8z6loVyI59S0=","
0000000070: 74 72 65 65 5f 68 65 61 64 5f 73 69 67 6e 61 74   tree_head_signat
0000000080: 75 72 65 22 3a 22 42 41 45 42 41 45 64 61 79 49   ure":"BAEBAEdayI
0000000090: 6a 58 6f 39 45 43 77 52 2b 36 71 74 71 50 43 43   jXo9ECwR+6qtqPCC
00000000a0: 37 71 35 59 42 37 35 2b 6d 31 32 56 63 63 4c 52   7q5YB75+m12VccLR
00000000b0: 73 7a 78 68 48 52 2b 72 33 38 66 48 6a 67 38 76   szxhHR+r38fHjg8v
00000000c0: 57 78 42 2f 66 31 59 44 31 75 55 45 46 54 31 62   WxB/f1YD1uUEFT1b
00000000d0: 68 38 79 33 53 41 59 6e 61 71 57 77 6f 55 46 49   h8y3SAYnaqWwoUFI
00000000e0: 76 38 63 71 44 76 78 2b 50 79 67 71 6a 76 68 42   v8cqDvx+PygqjvhB
00000000f0: 6e 5a 45 57 31 33 6d 44 76 30 2b 6a 42 6d 35 59   nZEW13mDv0+jBm5Y
0000000100: 43 68 59 36 55 4d 4b 4f 49 64 52 35 54 4d 31 35   ChY6UMKOIdR5TM15
0000000110: 72 4a 41 54 37 41 56 79 78 69 31 46 2f 36 51 36   rJAT7AVyxi1F/6Q6
--
$OBJECT_ID
Object ID: 40000000-0000-0000-0010-000000000000
Birth Volume ID: 19050000-0000-0000-1905-000000000000
Birth Object ID: 31015ed0-1900-ffff-ffff-ffff82794711
Birth Domain ID: ffffffff-8279-4711-0000-000000000000

***************************************************************************
***************************************************************************
MFT entry found at offset 0x2193d400
Attribute: In Use & File
Record Number: 59045
Link count: 2


$STANDARD_INFORMATION
Creation                       Modified                       MFT Altered                    Access Date                    Type
------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
2019-03-17 06:50:07 UTC+0000 2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:42 UTC+0000   Archive

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-03-17 06:50:07 UTC+0000 2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:43 UTC+0000   2019-03-17 07:04:42 UTC+0000   Users\Bob\DOCUME~1\EMPLOY~1\EMPLOY~1.XLS

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
```

**Réponse : EMPLOY~1.XLS**

#### 16 - This box was exploited and is running meterpreter. What was the infected PID ?

**Réponse : 3496**