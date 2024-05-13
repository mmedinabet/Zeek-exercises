<h1> Lab: Investigating Traffic Data with Zeek </h1>
<h2>Introduction</h2>
Welcome to the traffic data investigation lab! In this lab, you will be presented with various scenarios involving network traffic data. Your task is to analyze the provided data using Zeek, a powerful network analysis tool, to identify and mitigate potential security threats.

We recommend completing the Zeek room on TryHackMe first, as it will provide you with a comprehensive understanding of how to use Zeek for network analysis.

A virtual machine (VM) is attached to this lab, eliminating the need for SSH or RDP access. Utilize the "Split View" feature to interact with the VM effectively. Exercise files are located in the folder on the desktop, and a log cleaner script named "clear-logs.sh" is available in each exercise folder.

Getting the VM Started
Click the green "Start Machine" button at the top of Task 1.
Click the blue "Show Split View" button to split the screen.
Wait for the VM to load completely. Once loaded, the screen will resemble the image below.
Click on the terminal icon located in the middle of the VM screen on the right.
In the terminal window, navigate to the Exercise-Files directory using the command cd Desktop/Exercise-Files/ followed by ls to view the directory contents.

<h2> Task 1: Anomalous DNS </h2>
An alert has been triggered indicating "Anomalous DNS Activity." Your objective is to investigate the provided PCAP and retrieve artifacts to confirm the validity of the alert.

Move into the anomalous-dns directory using the command cd anomalous-dns/, then use ls to view the directory contents.
Investigate the dns-tunneling.pcap file and the dns.log file to determine the number of DNS records linked to the IPv6 address.
Use Zeek to analyze the dns-tunneling.pcap file by running the command zeek -r dns-tunneling.pcap. View the log files using ls.
Extract the necessary field from the dns.log file using command-line tools to find the number of occurrences of the specified DNS record associated with the IPv6 address.

![Screenshot 2024-05-13 3 30 31 PM](https://github.com/mmedinabet/Zeek-exercises/assets/142737434/99bbd3c1-bc0d-435d-9ebf-63174e198aed)

Answer the provided questions based on your analysis.
Questions:
What is the number of DNS records linked to the IPv6 address?
- Answer: 320

What is the longest connection duration found in the conn.log file?
![Screenshot 2024-05-13 3 33 12 PM](https://github.com/mmedinabet/Zeek-exercises/assets/142737434/1515f49a-ee02-49f9-a272-671049d91fb8)

Answer: 9.420791
How many unique domain queries are there in the dns.log file?
![Screenshot 2024-05-13 3 39 57 PM](https://github.com/mmedinabet/Zeek-exercises/assets/142737434/9756e52c-7a20-42d5-afd9-df4bf9773a10)

- Answer: 6

What is the IP address of the source host involved in abnormal DNS query activity?
![Screenshot 2024-05-13 3 41 28 PM](https://github.com/mmedinabet/Zeek-exercises/assets/142737434/e1cf37e8-0804-4552-8840-748adef2f208)

- Answer: 10.20.57.3

<h2> Task 2: Phishing</h2>
An alert triggered: "Phishing Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 

Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.

Investigate the http.log file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.

Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?

Investigate the extracted malicious .exe file. What is the given file name in Virustotal?

Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.

Investigate the http.log file. What is the request name of the downloaded malicious .exe file?

<h2>Task 3: Log4J/h2>
An alert triggered: "Log4J Exploitation Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 


Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?

Investigate the http.log file. Which tool is used for scanning?

Investigate the http.log file. What is the extension of the exploit file?

Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
