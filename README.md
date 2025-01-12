# Packet-Sniffer
This is a Python-based packet monitoring application with a graphical user interface (GUI) that allows users to sniff network packets in real time. The app uses the `scapy` library for packet sniffing and `tkinter` for the GUI.Also by taking a little help while I was stuck at places I took help of chatgpt to complete my project .

Scapy is a Python program that enables the user to send, sniff, dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack networks.In other words, Scapy is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. Scapy can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery. 

For more information about scapy view this documentation : https://scapy.readthedocs.io/en/latest/introduction.html

//Installation:

Install the below libraries in your VS code/pycharm terminal by running these commands:
-> pip install scapy 

install npcap from the official npcap site and configure it 

//Code explanation:

If you view the scapy documentation there is a lot of stuff in there and at first it might seem quiet difficult to understand the functions vbut atleast having the basic knowledge about scapy by watching tutorials in youtube is more than enough .  Making projects using scapy can help a lot in making cybersecurity projects . You just need to browse what you want to do like in this project we are going to create a packet/port sniffer and for that you'll be requiring it to break it down to smaller chunks like code for sniffing packets using scapy . at first by going through the documentation i found functions like haslayer() function to check if a packet contains a specific layer so that the ;ayers can be divided into TCP AND UDP separately . Upon more looking for a proper function to scan the port i found this stack overflow documentation    :   https://stackoverflow.com/questions/19311673/fetch-source-address-and-port-number-of-packet-scapy-script   

The code in this clearly has a full code for scanning the tcp ports :from scapy.all import *
def print_summary(pkt):
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
    if TCP in pkt:
        tcp_sport=pkt[TCP].sport
        tcp_dport=pkt[TCP].dport

        print " IP src " + str(ip_src) + " TCP sport " + str(tcp_sport) 
        print " IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport)

    # you can filter with something like that
    if ( ( pkt[IP].src == "192.168.0.1") or ( pkt[IP].dst == "192.168.0.1") ):
        print("!")

sniff(filter="ip",prn=print_summary)
# or it possible to filter with filter parameter...!
sniff(filter="ip and host 192.168.0.1",prn=print_summary)


///// By making a little change in this code by writting one more else if function to the same for UDP port , I was able to scan the ports . 

After this writting the code for  a simple python based GUI , I made buttons and lables for start , resume/pause and stop functions . 
Also by taking a little help while i was stuck at places i took help of chatgpt.


