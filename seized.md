# Seized

## Info

- Category : Digital Forensics
- SHA1SUM :	a2c209bb3c221bc70f3418e079e2a22db3cebc53
- Published : May 28, 2022
- Authors : 2phi and Nofix
- Size : 162 MB
- Tags : LINUX MEMORY CENTOS ROOTKIT

Unzip the challenge (pass: cyberdefenders.org), investigate this case, and answer the provided questions.

Use the latest version of Volatility, place the attached Volatility profile "Centos7.3.10.1062.zip" in the following path volatility/volatility/plugins/overlays/linux.

### Scenario

Using Volatility, utilize your memory analysis skills to Investigate the provided Linux memory snapshots and figure out attack details.

### Tools

- Volatility
- CyberChef
- grep

---

## Questions

### 1 - What is the CentOS version installed on the machine?

We use `grep` to find the OS version:

```
grep -a "Linux release" dump.mem
```

**Answer: 7.7.1908**

### 2 - There is a command containing a strange message in the bash history. Will you be able to read it?

We run `volatility` using the Linux profile given with the challenge

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_bash
```

We get the following result which seems to be the weird command:

```
2622 bash 2020-05-07 14:56:17 UTC+0000 echo "c2hrQ1RGe2wzdHNfc3Q0cnRfdGgzXzFudjNzdF83NWNjNTU0NzZmM2RmZTE2MjlhYzYwfQo=" > y0ush0uldr34dth1s.txt
```

By translating the b64 we have the flag:

**Answer: shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60}**

### 3 - What is the PID of the suspicious process?

We run `volatility` using the Linux profile given with the challenge

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_pslist
```

We see the PID 2854 which is an ncat

**Answer: 2854**

### 4 - The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

With the linux_bash plugin we see what the commands are, so what he was able to download.

We go to the github from which the attacker downloaded his files.

In one of the files we see a hidden message (in snapshot.py).

**Answer: shkCTF{th4t_w4s_4_dumb_b4ckd00r_86033c19e3f39315c00dca}**

### 5 - What are the IP address and the port used by the attacker?

We run `volatility` using the Linux profile given with the challenge. And the `netscan` plugin

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_netscan
```

We look at the addr ip which listens to port 12345. Because the backdoor has opened a connection on this port.

**Answer: 192.168.49.1:12345**

### 6 - What is the first command that the attacker executed?

The commands executed and the associated processes are analyzed.

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_psaux
```

After the ncat we see the command:

**Answer: python -c import pty; pty.spawn("/bin/bash")**

### 7 - After changing the user password, we found that the attacker still has access. Can you find out how?

**rc.local** is a file used to launch actions at startup.

We retrieve the pid of the modification action of the rc.local file. Then just dump it to analyze it

```
vol.py -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_dump_map --dump-dir output/ -p 3196
```

```
strings *.vma |grep -i '.ssh'
```

**Answer: shkCTF{rc.l0c4l_1s_funny_be2472cfaeed467ec9cab5b5a38e5fa0}**

### 8 - What is the name of the rootkit that the attacker used?

A rootkit most of the time tries to `hook` the system calls to modify them, in order to escalate its privileges.

We use the volatility plugin to see the system calls and see if there has been a `hook`

```
volatility -f dump.mem --profile=LinuxCentOS-7_7_1908-3_10_0-1062x64 linux_check_syscall | grep -i hook
```

The output of this command shows that there was a hook caused by the rootkit:

**Answer: sysemptyrect**


### 9 - The rootkit uses crc65 encryption. What is the key?

For this question one can simply grep the name of the rootkit into memory:

```
grep -a -i "sysemptyrect" dump.mem
```

We then have the key that is displayed

**Answer: 1337tibbartibbar**
