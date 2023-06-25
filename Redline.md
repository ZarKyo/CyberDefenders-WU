# Redline

## Info

- Category : Digital Forensics
- SHA1SUM : 7c54f50cefed2e2a8947368c0de41bbb665fe483
- Published : June 2, 2023
- Author : Ahmed Tammam
- Size : 839 MB
- Tags : Volatility NIDS Network Intrusion Detection System

Uncompress the challenge (pass: cyberdefenders.org)

### Scenario

As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System "NIDS". Your investigation will involve identifying the specific malware family employed in the attack, along with its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

### Tools

- Volatility
- Redline

---

## Questions

### Q1 - What is the name of the suspicious process?

```shell
vol2d -f /a/$(readlink -f MemoryDump.mem) imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/a/home/zarkyo/info/cyber/CyberDefenders-WU/MemoryDump.mem)
                      PAE type : No PAE
                           DTB : 0x1ad002L
                          KDBG : 0xf80762e1ab20L
          Number of Processors : 4
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff80761287000L
                KPCR for CPU 1 : 0xffff8a0094dc0000L
                KPCR for CPU 2 : 0xffff8a00949e8000L
                KPCR for CPU 3 : 0xffff8a0094b5d000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2023-05-21 23:02:39 UTC+0000
     Image local date and time : 2023-05-22 01:02:39 +0200
```

```shell
vol2d -f /a/$(readlink -f MemoryDump.mem) --profile=Win10x64_19041 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xffffad8185883180:System                              4      0    157      0 2023-05-21 22:27:10 UTC+0000
. 0xffffad81858f2080:Registry                         108      4      4      0 2023-05-21 22:26:54 UTC+0000
. 0xffffad8187835080:MemCompression                  1280      4     62      0 2023-05-21 22:27:49 UTC+0000
. 0xffffad81860dc040:smss.exe                         332      4      2      0 2023-05-21 22:27:10 UTC+0000
 0xffffad8186f2b080:wininit.exe                       552    444      1      0 2023-05-21 22:27:25 UTC+0000
. 0xffffad8186f4d080:services.exe                     676    552      7      0 2023-05-21 22:27:29 UTC+0000
.. 0xffffad818d374280:SecurityHealth                 5136    676      7      0 2023-05-21 22:32:01 UTC+0000
.. 0xffffad818e752080:svchost.exe                    5476    676      9      0 2023-05-21 22:58:08 UTC+0000
.. 0xffffad8187b94080:svchost.exe                    2076    676     10      0 2023-05-21 22:28:19 UTC+0000
.. 0xffffad818c532080:svchost.exe                    6696    676      8      0 2023-05-21 22:34:07 UTC+0000
.. 0xffffad818e88e140:svchost.exe                    7772    676      3      0 2023-05-21 22:36:03 UTC+0000
.. 0xffffad818d09f080:SgrmBroker.exe                 6200    676      7      0 2023-05-21 22:33:42 UTC+0000
.. 0xffffad81896ab080:vmtoolsd.exe                   2144    676     11      0 2023-05-21 22:28:19 UTC+0000
.. 0xffffad8187b34080:svchost.exe                    1892    676     14      0 2023-05-21 22:28:05 UTC+0000
.. 0xffffad818c426080:svchost.exe                    1116    676      6      0 2023-05-21 22:31:00 UTC+0000
.. 0xffffad818945c080:MsMpEng.exe                    1120    676     12      0 2023-05-21 22:10:01 UTC+0000
.. 0xffffad81896ae240:vm3dservice.ex                 2152    676      2      0 2023-05-21 22:28:19 UTC+0000
... 0xffffad8186619200:vm3dservice.ex                2404   2152      2      0 2023-05-21 22:28:32 UTC+0000
.. 0xffffad8187a112c0:svchost.exe                    1644    676      6      0 2023-05-21 22:27:58 UTC+0000
.. 0xffffad8187a2d2c0:svchost.exe                    1652    676     10      0 2023-05-21 22:27:58 UTC+0000
.. 0xffffad8187721240:svchost.exe                     448    676     54      0 2023-05-21 22:27:41 UTC+0000
... 0xffffad8189d07300:taskhostw.exe                 1600    448     10      0 2023-05-21 22:30:09 UTC+0000
... 0xffffad818d3d6080:oneetx.exe                    5480    448      6      0 2023-05-21 23:03:00 UTC+0000
... 0xffffad8189b30080:taskhostw.exe                 3876    448      8      0 2023-05-21 22:08:02 UTC+0000
... 0xffffad8189e94280:sihost.exe                    1392    448     11      0 2023-05-21 22:30:08 UTC+0000
... 0xffffad818dc5d080:taskhostw.exe                 6048    448      5      0 2023-05-21 22:40:20 UTC+0000
.. 0xffffad818ce06240:SearchIndexer.                 4228    676     15      0 2023-05-21 22:31:27 UTC+0000
.. 0xffffad818d07a080:svchost.exe                    3608    676      3      0 2023-05-21 22:41:28 UTC+0000
.. 0xffffad81896b3300:VGAuthService.                 2200    676      2      0 2023-05-21 22:28:19 UTC+0000
.. 0xffffad818dc88080:TrustedInstall                 6596    676      4      0 2023-05-21 22:58:13 UTC+0000
.. 0xffffad81877972c0:svchost.exe                    1196    676     34      0 2023-05-21 22:27:46 UTC+0000
.. 0xffffad8186f4a2c0:svchost.exe                    1232    676      7      0 2023-05-21 22:29:39 UTC+0000
.. 0xffffad8187758280:svchost.exe                     752    676     21      0 2023-05-21 22:27:43 UTC+0000
... 0xffffad8189c8b280:ctfmon.exe                    3204    752     12      0 2023-05-21 22:30:11 UTC+0000
.. 0xffffad8189d7c2c0:svchost.exe                    1064    676     15      0 2023-05-21 22:30:09 UTC+0000
.. 0xffffad818e888080:VSSVC.exe                      4340    676      3      0 2023-05-21 23:01:06 UTC+0000
.. 0xffffad8187acb200:spoolsv.exe                    1840    676     10      0 2023-05-21 22:28:03 UTC+0000
.. 0xffffad818761d240:svchost.exe                     824    676     22      0 2023-05-21 22:27:32 UTC+0000
... 0xffffad818cd93300:RuntimeBroker.                4116    824      3      0 2023-05-21 22:31:24 UTC+0000
... 0xffffad81876e8080:RuntimeBroker.                5656    824      0 ------ 2023-05-21 21:58:19 UTC+0000
... 0xffffad8185962080:RuntimeBroker.                5704    824      5      0 2023-05-21 22:32:44 UTC+0000
... 0xffffad818cad3240:StartMenuExper                3160    824     14      0 2023-05-21 22:31:21 UTC+0000
... 0xffffad818eb18080:ShellExperienc                6076    824     14      0 2023-05-21 22:11:36 UTC+0000
... 0xffffad818e84f300:ApplicationFra                7312    824     10      0 2023-05-21 22:35:44 UTC+0000
... 0xffffad818e8bb080:RuntimeBroker.                7336    824      2      0 2023-05-21 22:11:39 UTC+0000
... 0xffffad818e780080:TiWorker.exe                  2332    824      4      0 2023-05-21 22:58:13 UTC+0000
... 0xffffad818de5d080:HxTsr.exe                     5808    824      0 ------ 2023-05-21 21:59:58 UTC+0000
... 0xffffad818e893080:smartscreen.ex                7540    824     14      0 2023-05-21 23:02:26 UTC+0000
... 0xffffad818d176080:dllhost.exe                   1764    824      7      0 2023-05-21 22:32:48 UTC+0000
... 0xffffad818e6db080:TextInputHost.                8952    824     10      0 2023-05-21 21:59:11 UTC+0000
... 0xffffad818c09a080:RuntimeBroker.                4448    824      9      0 2023-05-21 22:31:33 UTC+0000
... 0xffffad818c054080:WmiPrvSE.exe                  3944    824     13      0 2023-05-21 22:30:44 UTC+0000
... 0xffffad8186f49080:SkypeBackgroun                 372    824      3      0 2023-05-21 22:10:00 UTC+0000
... 0xffffad818d099080:SearchApp.exe                 1916    824     24      0 2023-05-21 22:33:05 UTC+0000
... 0xffffad818eec8080:RuntimeBroker.                8264    824      4      0 2023-05-21 22:40:33 UTC+0000
... 0xffffad818d3ac080:SkypeApp.exe                  6644    824     49      0 2023-05-21 22:41:52 UTC+0000
... 0xffffad818ccc4080:SearchApp.exe                 7160    824     57      0 2023-05-21 22:39:13 UTC+0000
.. 0xffffad8185861280:msdtc.exe                       832    676      9      0 2023-05-21 22:29:25 UTC+0000
.. 0xffffad818ef86080:svchost.exe                    5964    676      5      0 2023-05-21 22:27:56 UTC+0000
.. 0xffffad81878020c0:svchost.exe                    1376    676     15      0 2023-05-21 22:27:49 UTC+0000
.. 0xffffad818d431080:svchost.exe                    8708    676      5      0 2023-05-21 22:57:33 UTC+0000
.. 0xffffad818796c2c0:svchost.exe                    1448    676     30      0 2023-05-21 22:27:52 UTC+0000
.. 0xffffad81876802c0:svchost.exe                     952    676     12      0 2023-05-21 22:27:36 UTC+0000
.. 0xffffad818774c080:svchost.exe                    1012    676     19      0 2023-05-21 22:27:43 UTC+0000
.. 0xffffad818c4212c0:svchost.exe                    3004    676      7      0 2023-05-21 22:30:55 UTC+0000
.. 0xffffad8185907080:dllhost.exe                    3028    676     12      0 2023-05-21 22:29:20 UTC+0000
.. 0xffffad81879752c0:svchost.exe                    1496    676     12      0 2023-05-21 22:27:52 UTC+0000
... 0xffffad818df2e080:audiodg.exe                   6324   1496      4      0 2023-05-21 22:42:56 UTC+0000
.. 0xffffad8187b65240:svchost.exe                    2024    676      7      0 2023-05-21 22:28:11 UTC+0000
.. 0xffffad8189b27080:svchost.exe                    2044    676     28      0 2023-05-21 22:49:29 UTC+0000
. 0xffffad8186fc6080:lsass.exe                        696    552     10      0 2023-05-21 22:27:29 UTC+0000
. 0xffffad818761b0c0:fontdrvhost.ex                   852    552      5      0 2023-05-21 22:27:33 UTC+0000
 0xffffad81861cd080:csrss.exe                         452    444     12      0 2023-05-21 22:27:22 UTC+0000
 0xffffad8186f450c0:winlogon.exe                      588    520      5      0 2023-05-21 22:27:25 UTC+0000
. 0xffffad818761f140:fontdrvhost.ex                   860    588      5      0 2023-05-21 22:27:33 UTC+0000
. 0xffffad81876e4340:dwm.exe                         1016    588     15      0 2023-05-21 22:27:38 UTC+0000
. 0xffffad818c02f340:userinit.exe                    3556    588      0 ------ 2023-05-21 22:30:28 UTC+0000
.. 0xffffad818c047340:explorer.exe                   3580   3556     76      0 2023-05-21 22:30:28 UTC+0000
... 0xffffad818db45080:notepad.exe                   5636   3580      1      0 2023-05-21 22:46:50 UTC+0000
... 0xffffad818e578080:Outline.exe                   6724   3580      0 ------ 2023-05-21 22:36:09 UTC+0000
.... 0xffffad818de82340:tun2socks.exe                4628   6724      0 ------ 2023-05-21 22:40:10 UTC+0000
.... 0xffffad818e88b080:Outline.exe                  4224   6724      0 ------ 2023-05-21 22:36:23 UTC+0000
... 0xffffad8189796300:vmtoolsd.exe                  3252   3580      8      0 2023-05-21 22:31:59 UTC+0000
... 0xffffad818d0980c0:msedge.exe                    5328   3580     54      0 2023-05-21 22:32:02 UTC+0000
.... 0xffffad818c553080:msedge.exe                   5156   5328     14      0 2023-05-21 22:28:22 UTC+0000
.... 0xffffad818d75f080:msedge.exe                   1144   5328     18      0 2023-05-21 22:32:38 UTC+0000
.... 0xffffad818d7a1080:msedge.exe                   6292   5328     20      0 2023-05-21 22:06:15 UTC+0000
.... 0xffffad8187a39080:msedge.exe                   8896   5328     18      0 2023-05-21 22:28:21 UTC+0000
.... 0xffffad818d7b3080:msedge.exe                   5340   5328     10      0 2023-05-21 22:32:39 UTC+0000
.... 0xffffad818dee5080:msedge.exe                   7964   5328     19      0 2023-05-21 22:22:09 UTC+0000
.... 0xffffad818d515080:msedge.exe                   4396   5328      7      0 2023-05-21 22:32:19 UTC+0000
.... 0xffffad818e54c340:msedge.exe                   2388   5328     18      0 2023-05-21 22:05:35 UTC+0000
.... 0xffffad818c0ea080:msedge.exe                   6544   5328     18      0 2023-05-21 22:22:35 UTC+0000
.... 0xffffad818d75b080:msedge.exe                   4544   5328     14      0 2023-05-21 22:32:39 UTC+0000
... 0xffffad818ef81080:FTK Imager.exe                8920   3580     20      0 2023-05-21 23:02:28 UTC+0000
... 0xffffad818d143080:FTK Imager.exe                2228   3580     10      0 2023-05-21 22:43:56 UTC+0000
... 0xffffad818979d080:SecurityHealth                 464   3580      3      0 2023-05-21 22:31:59 UTC+0000
 0xffffad8186f1b140:csrss.exe                         528    520     14      0 2023-05-21 22:27:25 UTC+0000
 0xffffad8189b41080:oneetx.exe                       5896   8844      5      0 2023-05-21 22:30:56 UTC+0000
. 0xffffad818d1912c0:rundll32.exe                    7732   5896      1      0 2023-05-21 22:31:53 UTC+0000
```

Oneetx.exe is a disguise name chosen by Amadey dropper developers to hide their malware among other processes. Windows tracks all processes running in the system, and displays what it found in Task Manager. Obviously, obfuscated names like sv39103.exe will attract attention and raise suspicion. That is the reason why hackers opt for some ordinary names. 

**Answer : oneetx.exe**

### Q2 - What is the child process name of the suspicious process?

**Answer : rundll32.exe**

### Q3 - What is the memory protection applied to the suspicious process memory region?

```shell
vol2d -f /a/$(readlink -f MemoryDump.mem) --profile=Win10x64_19041 malfind
Volatility Foundation Volatility Framework 2.6.1
Process: oneetx.exe Pid: 5896 Address: 0x400000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: PrivateMemory: 1, Protection: 6

0x0000000000400000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x0000000000400010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x0000000000400020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x0000000000400030  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00   ................

0x0000000000400000 4d               DEC EBP
0x0000000000400001 5a               POP EDX
0x0000000000400002 90               NOP
0x0000000000400003 0003             ADD [EBX], AL
0x0000000000400005 0000             ADD [EAX], AL
0x0000000000400007 000400           ADD [EAX+EAX], AL
0x000000000040000a 0000             ADD [EAX], AL
0x000000000040000c ff               DB 0xff
0x000000000040000d ff00             INC DWORD [EAX]
0x000000000040000f 00b800000000     ADD [EAX+0x0], BH
0x0000000000400015 0000             ADD [EAX], AL
0x0000000000400017 004000           ADD [EAX+0x0], AL
0x000000000040001a 0000             ADD [EAX], AL
0x000000000040001c 0000             ADD [EAX], AL
0x000000000040001e 0000             ADD [EAX], AL
0x0000000000400020 0000             ADD [EAX], AL
0x0000000000400022 0000             ADD [EAX], AL
0x0000000000400024 0000             ADD [EAX], AL
0x0000000000400026 0000             ADD [EAX], AL
0x0000000000400028 0000             ADD [EAX], AL
0x000000000040002a 0000             ADD [EAX], AL
0x000000000040002c 0000             ADD [EAX], AL
0x000000000040002e 0000             ADD [EAX], AL
0x0000000000400030 0000             ADD [EAX], AL
0x0000000000400032 0000             ADD [EAX], AL
0x0000000000400034 0000             ADD [EAX], AL
0x0000000000400036 0000             ADD [EAX], AL
0x0000000000400038 0000             ADD [EAX], AL
0x000000000040003a 0000             ADD [EAX], AL
0x000000000040003c 0001             ADD [ECX], AL
0x000000000040003e 0000             ADD [EAX], AL
```

**Answer : PAGE_EXECUTE_READWRITE**

### Q4 - What is the name of the process responsible for the VPN connection?

In the pstree, we can see :

```shell
... 0xffffad818e578080:Outline.exe                   6724   3580      0 ------ 2023-05-21 22:36:09 UTC+0000
.... 0xffffad818de82340:tun2socks.exe                4628   6724      0 ------ 2023-05-21 22:40:10 UTC+0000
.... 0xffffad818e88b080:Outline.exe                  4224   6724      0 ------ 2023-05-21 22:36:23 UTC+0000
```

**Answer : Outline.exe**

### Q5 - What is the attacker's IP address?

```shell
vol3d -f /a/$(readlink -f MemoryDump.mem) windows.netscan.NetScan | grep -i "oneetx.exe"   
0xad818de4aa20.0TCPv4   10.0.85.2DB scan55462fin77.91.124.20    80      CLOSED  5896    oneetx.exe      2023-05-21 23:01:22.000000 
0xad818e4a6900  UDPv4   0.0.0.0 0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 
0xad818e4a6900  UDPv6   ::      0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 
0xad818e4a9650  UDPv4   0.0.0.0 0       *       0               5480    oneetx.exe      2023-05-21 22:39:47.000000 
```

**Answer : 77.91.124.20**

### Q6 - Based on the previous artifacts. What is the name of the malware family?

**Answer : RedLine Stealer**

### Q7 - What is the full URL of the PHP file that the attacker visited?

```shell
strings MemoryDump.mem > strings.txt
strings -el MemoryDump.mem >> strings.txt
```

```shell
grep -Eo 'https?://[^[:space:]]+' strings.txt | grep -i "77.91.124.20" | grep ".php"

http://77.91.124.20/store/games/index.php
```
**Answer : http://77.91.124.20/store/games/index.php**

### Q8 - What is the full path of the malicious executable?

```shell
vol3d -f /a/$(readlink -f MemoryDump.mem) windows.filescan.FileScan > files.txt
```

```shell
cat files.txt| grep -i oneetx        
0xad818d436c70  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
0xad818da36c30  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
0xad818ef1a0b0  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe  216
```

**Answer : C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe**