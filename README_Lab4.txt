README.txt


Vanessa Venkataraman
alarm.py


The purpose of this program is to analyze network packets for incidents. The program is correctly implemented to be able to detect a NULL scan, FIN scan, Xmas scan, Usernames and password sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP, Nikto scans, SMB scan, RDP scan, and VNC scan.


I spent about 16 hours on this assignment…


I utilized class notes, stackoverflow, Scapy documentation and ChatGPT to receive answers for syntactical questions and for guidance on implementation strategies. I also collaborated with Ming for guidance on an error I was unable to discover at the time.


Additional dependencies: base64


I think the heuristics used in this assignments to determine incidents are pretty decent because the functionality would be similar to a person reading live results through Wireshark.


If I had spare time in the future, I would investigate other ports that may be prone to incidents, not just the obvious ports.