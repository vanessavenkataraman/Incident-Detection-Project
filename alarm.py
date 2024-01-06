#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

#initialize variables - count for incidents, username string, and password string
num_incidents = 0
username = ""
password = ""

def packetcallback(packet):
  try:
    #create global variables
    global num_incidents
    global username
    global password

    # NULL Scan
    if packet[TCP].flags == 0:
      num_incidents = num_incidents+1
      ip = str(packet[IP].src)
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": NULL scan is detected from " + ip + "(" + port + ")!")
    # FIN Scan
    if packet[TCP].flags == 'F':
      num_incidents = num_incidents+1
      ip = str(packet[IP].src)
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": FIN scan is detected from " + ip + "(" + port + ")!")
    # Xmas Scan
    if packet[TCP].flags == 'F'+'P'+'U':
      num_incidents = num_incidents+1
      ip = str(packet[IP].src)
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": XMAS scan is detected from " + ip + "(" + port + ")!")
    # Nikto Scan
    if packet[TCP].dport == 80:
      packet_contents = packet[TCP].load.decode("ascii")
      if "Nikto" in packet_contents:
        num_incidents = num_incidents+1
        ip = str(packet[IP].src)
        port = str(packet[TCP].dport)
        print("ALERT #" + str(num_incidents) + ": Nikto scan is detected from " + ip + "(" + port + ")!")
      #HTTP usernames and passwords
    # SMB Protocol
    if packet[TCP].dport == 445:
      num_incidents = num_incidents+1
      ip = str(packet[IP].src)
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": SMB scan is detected from " + ip + "(" + port + ")!")
    # RDP Protocol
    if packet[TCP].dport == 3389:
      num_incidents = num_incidents+1
      ip = str(packet[IP].src)
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": RDP scan is detected from " + ip + "(" + port + ")!")
    # VNC Instances
    if packet[TCP].dport == 5900:
      num_incidents = num_incidents+1
      ip = packet[IP].src
      port = str(packet[TCP].dport)
      print("ALERT #" + str(num_incidents) + ": VNC scan is detected from " + ip + "(" + port + ")!")
    # HTTP usernames and password
    if packet.haslayer(TCP):
        packet_contents = packet[TCP].load.decode("ascii").strip()
        if "Authorization: Basic" in packet_contents:
            credentials = packet_contents.split("Authorization: Basic ")[1]
            credentials = credentials.splitlines()[0]
            decode = base64.b64decode(credentials).decode('utf-8')
            num_incidents = num_incidents+1
            [username, password] = decode.split(":")
            print(f"ALERT #" + str(num_incidents) + ": Usernames and passwords sent in-the-clear (HTTP) (username: " + username + ", password: " + password + ")")
    
    # FTP usernames and passwords
    if packet.haslayer(TCP) and packet[TCP].dport == 21:
        packet_contents = packet[TCP].load.decode("ascii")
        if "USER" in packet[TCP].load.decode("ascii"):
            username = str(packet[TCP].load.decode("ascii"))
            username = username.lstrip("USER ")
            packet_contents = packet[TCP].load.decode("ascii")
        if "PASS" in packet_contents:
            num_incidents = num_incidents+1
            password = str(packet_contents)
            password = password.lstrip("PASS")
            print("ALERT #" + str(num_incidents) + ": Usernames and passwords sent in-the-clear (FTP) (username: " + username + ", password: " + password + ")")
    # IMAP usernames and passwords
    if packet.haslayer(TCP) and packet[TCP].dport == 993 or packet[TCP].dport == 143:
        packet_contents = packet[TCP].load.decode("ascii")
        if "LOGIN" in packet_contents:
          num_incidents = num_incidents+1
          username = packet_contents.strip().split(" ")[2]
          password = packet_contents.strip().split(" ")[3]
          print(f"ALERT #" + str(num_incidents) + ": Usernames and passwords sent in-the-clear (IMAP) (username: " + str(username) + ", password: "+ str(password) + ")")
   
  except:
    pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
