# Bucket

## Info 

- Category : Digital Forensics
- SHA1SUM : fb393619f09c8e9d7272f305329601645e5aa952
- Published : Dec. 7, 2021
- Author : Scott Piper
- Size : 356 Bytes
- Tags : AWS cloud IR 'log analysis'
 	
Unzip the challenge (pass: cyberdefenders.org)

### Instructions

Use the provided credentials to access AWS cloud trail logs and answer the questions.
 
### Scenario

Welcome, Defender! As a soc analyst, we're granting you access to the AWS account called "Security" as an IAM user. This account contains a copy of the logs during the time period of the incident and has the ability to assume the "Security" role in the target account so you can look around to spot the misconfigurations that allowed for this attack to happen.

### Credentials

Your IAM credentials for the Security account :
- Login: https://flaws2-security.signin.aws.amazon.com/console
- Account ID: 322079859186
- Username: security
- Password: password
- Access Key: AKIAIUFNQ2WCOPTEITJQ
- Secret Key: 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
 
### Environment

The credentials above give you access to the Security account, which can assume the role of "security" in the Target account. You also have access to an S3 bucket, named flaws2_logs, in the Security account, that contains the CloudTrail logs recorded during a successful compromise

![account](./img/account.jpg)

### Tools

- AWS-CLI
- jq

---

## Questions

### Q1 - What is the full AWS CLI command used to configure credentials?

```shell
aws configure

AWS Access Key ID [None]: AKIAIUFNQ2WCOPTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: 
Default output format [None]: json
```

**Answer : aws configure**

### Q2 - What is the 'creation' date of the bucket 'flaws2-logs'?

I logged into the AWS Management Console. We need to select the S3 service. 

![bucket-creation-date](./img/bucket-creation-date.png)

**Answer : 2018-11-19 20:54:31 UTC**

### Q3 - What is the name of the first generated event -according to time?

Download log in my computer :

```shell
aws s3 sync s3://flaws2-logs .
```

``shell
cd AWSLogs/653711331788/CloudTrail/us-east-1/2018/11/28/

gunzip 653711331788_CloudTrail_us-east-1_20181128T2235Z_cR9ra7OH1rytWyXY.json.gz
```

```shell
cat 653711331788_CloudTrail_us-east-1_20181128T2235Z_cR9ra7OH1rytWyXY.json | jq

{
  "Records": [
    {
      "eventVersion": "1.05",
      "userIdentity": {
        "type": "AWSService",
        "invokedBy": "ecs-tasks.amazonaws.com"
      },
      "eventTime": "2018-11-28T22:31:59Z",
      "eventSource": "sts.amazonaws.com",
      "eventName": "AssumeRole",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "ecs-tasks.amazonaws.com",
      "userAgent": "ecs-tasks.amazonaws.com",
      "requestParameters": {
        "roleSessionName": "d190d14a-2404-45d6-9113-4eda22d7f2c7",
        "roleArn": "arn:aws:iam::653711331788:role/level3"
      },

[...]
```

`"eventName": "AssumeRole",`

**Answer : AssumeRole**

### Q4 - What source IP address generated the event dated 2018-11-28 at 23:03:20 UTC?

I made a python script to get informations in json logs :

```python
import json
import sys

def parse_logs(json_file):
    with open(json_file) as file:
        data = json.load(file)
        
    for record in data['Records']:
        event_time = record['eventTime']
        source_ip = record['sourceIPAddress']
        event_name = record['eventName']
        
        print(f"Event Time: {event_time}")
        print(f"Source IP Address: {source_ip}")
        print(f"Event Name: {event_name}")
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Give a JSON file as argument")
    else:
        json_file = sys.argv[1]
        parse_logs(json_file)
```

Get informations on every files :

```shell
for file in AWSLogs/*.json; do python3 get_info.py "$file"; done | grep -i -C 5 2018-11-28T23:03:20

Event Time: 2018-11-28T23:03:11Z
Source IP Address: 104.102.221.250
Event Name: GetObject

Event Time: 2018-11-28T23:03:20Z
Source IP Address: apigateway.amazonaws.com
Event Name: Invoke

Event Time: 2018-11-28T23:03:50Z
Source IP Address: 34.234.236.212
--

Event Time: 2018-11-28T23:03:12Z
Source IP Address: lambda.amazonaws.com
Event Name: AssumeRole

Event Time: 2018-11-28T23:03:20Z
Source IP Address: 34.234.236.212
Event Name: CreateLogStream

Event Time: 2018-11-28T23:03:13Z
Source IP Address: 34.234.236.212
```

**Answer : 34.234.236.212**

### Q5 - Which IP address does not belong to Amazon AWS infrastructure?

Only 2 IPs are in the logs : `104.102.221.250` and `34.234.236.212`

```shell
nslookup 34.234.236.212               
212.236.234.34.in-addr.arpa     name = ec2-34-234-236-212.compute-1.amazonaws.com.

nslookup 104.102.221.250 
250.221.102.104.in-addr.arpa    name = a104-102-221-250.deploy.static.akamaitechnologies.com.
```

**Answer : 104.102.221.250**

### Q6 - Which user issued the 'ListBuckets' request?

```shell
grep -i ListBuckets 653711331788_CloudTrail_us-east-1_20181128T2*

653711331788_CloudTrail_us-east-1_20181128T2310Z_jQajCuiobojD8I4y.json:{"Records":[{"eventVersion":"1.05","userIdentity":....
```

We got only 1 result with the `grep` (pretty cool) :

```shell
cat 653711331788_CloudTrail_us-east-1_20181128T2310Z_jQajCuiobojD8I4y.json | jq                                                                              
{
  "Records": [
    {
      "eventVersion": "1.05",
      "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAJQMBDNUMIKLZKMF64:d190d14a-2404-45d6-9113-4eda22d7f2c7",
        "arn": "arn:aws:sts::653711331788:assumed-role/level3/d190d14a-2404-45d6-9113-4eda22d7f2c7",
        "accountId": "653711331788",
        "accessKeyId": "ASIAZQNB3KHGNXWXBSJS",
        "sessionContext": {
          "attributes": {
            "mfaAuthenticated": "false",
            "creationDate": "2018-11-28T22:31:59Z"
          },
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAJQMBDNUMIKLZKMF64",
            "arn": "arn:aws:iam::653711331788:role/level3",
            "accountId": "653711331788",
            "userName": "level3"
          }
        }
      },
      "eventTime": "2018-11-28T23:09:28Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "ListBuckets",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "104.102.221.250",
      "userAgent": "[aws-cli/1.16.19 Python/2.7.10 Darwin/17.7.0 botocore/1.12.9]",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "4698593B9338B27F",
      "eventID": "65e111a0-83ae-4ba8-9673-16291a804873",
      "eventType": "AwsApiCall",
      "recipientAccountId": "653711331788"
    }
  ]
}
```

**Answer : level3**

### Q7 - What was the first request issued by the user 'level1'?

```shell
grep -rl "level1" AWSLogs/

AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2305Z_83VTWZ8Z0kiEC7Lq.json
AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2305Z_zKlMhON7EpHala9u.json
AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2310Z_7J9NEIxrjJsrlXSd.json
AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2310Z_A1lhv3sWzzRIBFVk.json
AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2310Z_jJW5HfNtz7kOnvcP.json
```

The log files are sorted by date thanks to their similar name and a specific part linked to the timestamp (`*_20181128T2305Z_*`) which allows to know that the first request is in the first file of the list.

```shell
cat AWSLogs/653711331788_CloudTrail_us-east-1_20181128T2305Z_83VTWZ8Z0kiEC7Lq.json | jq                                                                                               
{
  "Records": [
    {
      "eventVersion": "1.04",
      "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAIBATWWYQXZTTALNCE:level1",
        "arn": "arn:aws:sts::653711331788:assumed-role/level1/level1",
        "accountId": "653711331788",
        "accessKeyId": "ASIAZQNB3KHGIGYQXVVG",
        "sessionContext": {
          "attributes": {
            "mfaAuthenticated": "false",
            "creationDate": "2018-11-28T23:03:12Z"
          },
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAIBATWWYQXZTTALNCE",
            "arn": "arn:aws:iam::653711331788:role/service-role/level1",
            "accountId": "653711331788",
            "userName": "level1"
          }
        }
      },
      "eventTime": "2018-11-28T23:03:12Z",
      "eventSource": "logs.amazonaws.com",
      "eventName": "CreateLogStream",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "34.234.236.212",
      "userAgent": "awslambda-worker",
      "errorCode": "AccessDenied",
      "errorMessage": "User: arn:aws:sts::653711331788:assumed-role/level1/level1 is not authorized to perform: logs:CreateLogStream on resource: arn:aws:logs:us-east-1:653711331788:log-group:/aws/lambda/level1:log-stream:2018/11/28/[$LATEST]2d75b45ba94f495598fd2fed9f3ca60e",
      "requestParameters": null,
      "responseElements": null,
      "requestID": "c80afb02-f361-11e8-b660-f9fa07f60344",
      "eventID": "77b02a51-70c8-465b-94df-579c1fe42a5c",
      "eventType": "AwsApiCall",
      "recipientAccountId": "653711331788"
    }
  ]
}
```

**Answer : CreateLogStream**
