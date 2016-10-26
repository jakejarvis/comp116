#! /usr/bin/env python

import sys, getopt
import base64
import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)   # https://stackoverflow.com/questions/13249341/surpress-scapy-warning-message-when-importing-the-module
from scapy.all import *

alert_count = 0

def live_scan(interface):
    print "Sniffing interface %s..." % interface
    try:
        sniffed = sniff(iface=interface, prn=check_packet)
    except:
        print "ERROR: Network interface failed"
        exit()





def pcap_scan(file):
    print "Scanning %s..." % file

    try:
        pcap_file = rdpcap(file)
    except IOError:
        print "ERROR: %s not found. Please save the pcap you wish to decode in this folder." % (file)
        exit()

    for packet in pcap_file:
        check_packet(packet)




# 1. NULL scan
def check_null(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 0:
        alarm(packet, "NULL scan", "TCP", "")

# 2. FIN scan
def check_fin(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 1:
        alarm(packet, "FIN scan", "TCP", "")
#    return (packet.haslayer(TCP) and packet[TCP].flags == 0x01)

# 2. Xmas scan
def check_xmas(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 41:
        alarm(packet, "Xmas scan", "TCP", "Merry Christmas!")


# 4. Usernames and passwords sent in-the-clear
def check_cleartext(packet):
    # HTTP passwords
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        if "Authorization: Basic" in packet.load:
            for line in packet.load.splitlines():
                if "Authorization: Basic" in line:
                    credentials_encoded = line.split("Authorization: Basic ")[1]
                    credentials = base64.b64decode(credentials_encoded)
                    alarm(packet, "HTTP credential", "HTTP", credentials)

    # IMAP passwords
    if packet.haslayer(TCP) and packet[TCP].dport == 143 and packet.haslayer(Raw):
        if "LOGIN" in packet.load:
            alarm(packet, "IMAP credential", "IMAP", packet.load)

    # FTP passwords
    if packet.haslayer(TCP) and packet[TCP].dport == 21 and packet.haslayer(Raw):
        if "USER" in packet.load or "PASS" in packet.load:
            alarm(packet, "FTP credential", "FTP", packet.load)


# 5. Credit card numbers sent in-the-clear
def check_cc(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80) and packet.haslayer(Raw):
        visa = re.search(r'^4\d{3}([\ \-]?)\d{4}\1\d{4}\1\d{4}$', packet.load)
        master = re.search(r'^5\d{3}([\ \-]?)\d{4}\1\d{4}\1\d{4}$', packet.load)
        discover = re.search(r'^6011([\ \-]?)\d{4}\1\d{4}\1\d{4}$', packet.load)
        amex = re.search(r'^3\d{3}([\ \-]?)\d{6}\1\d{5}$', packet.load)

        if visa:
            alarm(packet, "VISA card number", "HTTP", visa)
        elif master:
            alarm(packet, "MasterCard card number", "HTTP", master)
        elif discover:
            alarm(packet, "Discover card number", "HTTP", discover)
        elif amex:
            alarm(packet, "American Express card number", "HTTP", amex)

# 6. Nikto scan
def check_nikto(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        if "User-Agent: Mozilla/5.00 (Nikto" in packet.load:
            alarm(packet, "Nikto scan", "HTTP", packet.load.splitlines()[0])


# 10. phpMyAdmin
def check_PMA(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        if "phpmyadmin" in packet.load.lower() or "pma" in packet.load.lower():
            alarm(packet, "phpMyAdmin snooping", "HTTP", packet.load.splitlines()[0])



def check_packet(packet):
    # 1. NULL scan
    check_null(packet[0])

    # 2. FIN scan
    check_fin(packet[0])

    # 3. Xmas scan
    check_xmas(packet[0])

    # 4. Usernames and passwords sent in-the-clear
    check_cleartext(packet[0])

    # 5. Credit card numbers sent in-the-clear
    check_cc(packet[0])

    # 6. Nikto scan
    check_nikto(packet[0])

    # 7. Rob Graham's Masscan

    # 9. Shellshock vulnerability scan

    # 10. phpMyAdmin
    check_PMA(packet[0])



def alarm(packet, vul, proto, info):
    global alert_count
    alert_count += 1
    print "ALERT #%s: %s is detected from %s (%s) (%s)!" % (alert_count, vul, packet[0][IP].src, proto, info)



def main(argv):
    interface = ""
    file = ""

    try:
        opts, args = getopt.getopt(argv, "hi:r:", ["help"])
    except getopt.GetoptError:
        print "ERROR: Invalid arguments"
        exit()

    for opt, arg in opts:
        if opt == "-h" or opt == "--help":
            print "usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]"
            print ""
            print "A network sniffer that identifies basic vulnerabilities"
            print ""
            print "optional arguments:"
            print "  -h, --help    show this help message and exit"
            print "  -i INTERFACE  Network interface to sniff on"
            print "  -r PCAPFILE   A PCAP file to read"
            exit()
        elif opt == "-i":
            interface = arg
        elif opt == "-r":
            file = arg
        else:
            print "ERROR: Invalid arguments"
            exit()

    if interface:
        live_scan(interface)
    elif file:
        pcap_scan(file)
    else:
        live_scan("eth0")


if __name__ == "__main__":
    main(sys.argv[1:])
