# Network Sniffer

This Python script allows you to capture and analyze network traffic using raw sockets. It dissects Ethernet frames, IPv4 packets, ICMP, TCP, and UDP segments, providing details about each packet it encounters.

## Prerequisites

- Python (version 3.x recommended)
- Elevated privileges (sudo) to run the script due to the use of raw sockets

## Usage

1. Save the script as `network_sniffer.py`.

2. Open a terminal and navigate to the directory containing the script.

3. Run the script with elevated privileges:

   ```bash
   sudo python network_sniffer.py


The script will continuously capture and print information about network packets.

To stop the script, press Ctrl+C in the terminal.

Output
The script prints information about Ethernet frames, IPv4 packets, ICMP, TCP, and UDP segments. The output will vary based on the actual network traffic received.

Disclaimer
Use this script responsibly and ensure compliance with applicable laws and regulations. Unauthorized network monitoring or interception of data may be illegal in some jurisdictions.

Author
bharath kanne

License
This project is licensed under the MIT License.


Feel free to customize this README file based on your preferences and provide additional details about the project if needed.
