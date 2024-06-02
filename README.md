
HTTP Sniffer Tool

This tool captures and logs HTTP requests and ARP packets on a specified network interface. It extracts and logs details such as HTTP methods, source and destination IP addresses, requested URLs, and any credentials found in POST requests.
Features

    Captures HTTP requests and ARP packets.
    Logs HTTP method, source IP, destination IP, and requested URL.
    Extracts and logs POST data, including usernames and passwords if present.
    Saves captured data to a file captured_data.txt in the current working directory.

Prerequisites

    Python 3
    Scapy library

Installation

    Clone the repository:

    bash

	git clone <repository_url>
	cd <repository_directory>

Install Scapy:

bash

    pip install scapy

Usage

    Run the sniffer tool with root privileges:

    bash

sudo python3 http_sniffer.py -i <interface>

Replace <interface> with your network interface name (e.g., eth0, wlan0).

Specify the network interface:

The -i or --interface argument is required to specify the network interface to sniff data on.

Example:

bash

    sudo python3 http_sniffer.py -i eth0

Output

    The captured data will be saved to captured_data.txt in the current working directory.
    The tool will also print the captured data to the console.

Example Output

Console:

csharp

HTTP GET Request from 192.168.1.100 to 93.184.216.34: http://example.com
POST Request from 192.168.1.100 to 93.184.216.34 with payload: username=test&password=1234
Login attempt: username='test', password='1234' from 192.168.1.100 to 93.184.216.34
ARP Packet: ARP who-has 192.168.1.1 says 192.168.1.100

Captured Data File (captured_data.txt):

csharp

HTTP GET Request from 192.168.1.100 to 93.184.216.34: http://example.com
POST Request from 192.168.1.100 to 93.184.216.34 with payload: username=test&password=1234
Login attempt: username='test', password='1234' from 192.168.1.100 to 93.184.216.34
ARP Packet: ARP who-has 192.168.1.1 says 192.168.1.100

Notes

    Ensure you have the necessary permissions to run this script and capture network packets.
    This tool is intended for educational and ethical purposes only. Unauthorized sniffing and data capture is illegal and unethical.

Troubleshooting

    Permission Denied:
    Make sure to run the script with sudo to ensure it has the necessary permissions to capture network packets.
    No Data Captured:
    Verify that you have specified the correct network interface.

License

This project is licensed under the MIT License - see the LICENSE file for details.
