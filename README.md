## NoThink   
  http://www.nothink.org/blacklist/blacklist_ssh_week.txt

### Overview
 NoThink is known for honeypot statistics, data and others stuff about malware and network security.
 ##### Honeypot
 These pages are free and automatically created. You can find statistics, data and other stuff about malware.
 NoThink Honeypot  provides  statistical data in three types 
 ##### NoThink Honeypot SSH feeds
   The followings SSH blacklists (updated every day and in text format) contains IP addresses of hosts which tried to bruteforce into my honeypot located in Italy.
   Consider to use Detux to analyze linux malwares on x86, x86-64, ARM, MIPS and MIPSEL cpu architecture.
   For more information visit  http://www.nothink.org/honeypot_ssh.php
 ##### NoThink Honeypot Telnet feeds
   The followings Telnet blacklists (updated every day and in text format) contains IP addresses of hosts which tried to bruteforce into my honeypot located in Italy.
   The honeypot simulates a home router with a weak password and the most usual commands.
   For more information visit  http://www.nothink.org/honeypot_telnet.php 
 ##### NoThink Honeypot SNMP feeds
   For more information visit  http://www.nothink.org/honeypot_snmp.php
   

### Using the NoThink feed API
 The NoThink feed API is found on github at
 
 https://github.com/dnif/enrich-nothink

#### Getting started with NoThink feed API

1. #####    Login to your Data Store, A10 containers  
   ACCESS DNIF CONTAINER VIA SSH : [Click To Know How](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/enrichment_plugin’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/enrichment_plugin/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/enrich-nothink.git nothink
```
### API feed output structure
  | Fields        | Description  |
| ------------- |:-------------:|
| EvtType      | An IP |
| EvtName      | The IOC      |
| IntelRef | Feed Name      |
| IntelRefURL | Feed URL      |
| ThreatType | DNIF Feed Identification Name |      

An example of API feed output
```
 {'EvtType': 'IPv4', 
 'EvtName': '98.251.8.60', 
 'AddFields': {
 'IntelRef': ['NOTHINK'],
 'IntelRefURL': ['http://www.nothink.org/blacklist/blacklist_ssh_week.txt'], 
 'ThreatType': ['SSH blacklist'] }}
```
