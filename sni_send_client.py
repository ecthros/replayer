### Will not support IP Fragmentation (yet)

from scapy.all import *
import socket
import ssl

SERVER_IP = "18.182.65.55"
SERVER_PORT = 443
CLIENT_IP = "222.73.130.49"

INITIAL_SEQNO = random.randint(1000, 9999999)
#CLIENT_PORT = random.randint(1024,65535)
CLIENT_PORT = 57576
DEBUG = True

PCAP_FILE = "george_tcpdump_w_rst_drop.pcap"
# Send SYN, receive SA
SYN_PACKET=IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=CLIENT_PORT,dport=SERVER_PORT,flags='S',seq=INITIAL_SEQNO)
print(SYN_PACKET)
SYNACK_PACKET=sr1(SYN_PACKET)
print("received sa")
INITIAL_ACKNO = SYNACK_PACKET.seq
if DEBUG:
    print("Initial Ack: %s" % (INITIAL_ACKNO))
# Send ACK
send(IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags='A', seq=SYNACK_PACKET.ack, ack=SYNACK_PACKET.seq + 1))

#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.settimeout(30)

#sock.connect((SERVER_IP, SERVER_PORT))
packets = rdpcap(PCAP_FILE)

for packet in packets:
    if packet[IP].src == CLIENT_IP and packet[TCP].flags == "PA":
        #print(str(packet[TCP].payload).encode())
        #sock.send(packet[TCP].load)
        #time.sleep(1)
        # We need to edit the seq and ack numbers for each packet. A
        # FOr now, let's not worry about the wrap-around problem
        packet[TCP].seq = packet[TCP].seq - SEQNO_DIFFERENCE
        packet[TCP].ack = packet[TCP].ack - ACKNO_DIFFERENCE
        packet[TCP].sport = CLIENT_PORT
        if DEBUG:
            print(packet[TCP].dport)
            print("Sending Packet")
        send(packet)
        #send(IP(src=CLIENT_IP, dst=SERVER_IP)/packet[TCP], verbose=True, iface="eth0")
        time.sleep(1)
    elif packet[IP].src == SERVER_IP and packet[TCP].flags == "SA":
        INITIAL_SEQNO_FROM_PCAP = packet[TCP].ack - 1
        if DEBUG:
            print("Initial Seqno from PCAP: %s" % (INITIAL_SEQNO_FROM_PCAP))
        INITIAL_ACKNO_FROM_PCAP = packet[TCP].seq - 1
        SEQNO_DIFFERENCE = INITIAL_SEQNO_FROM_PCAP - INITIAL_SEQNO
        ACKNO_DIFFERENCE = INITIAL_ACKNO_FROM_PCAP - INITIAL_ACKNO
    else:
        pass #print(packet[TCP].flags)
#sock.close()
