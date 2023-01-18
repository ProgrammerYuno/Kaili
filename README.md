PCAP Information Extractor

A tool for extracting information from a PCAP file.

Requirements

- Scapy
- argparse
-OpenSSL

Usage
python pcap_info_extractor.py <pcapfile> [-s <src IP>] [-d <dst IP>] [-o <output file>]

Description
This script uses the Scapy library to read in the PCAP file and parse its contents. It then uses regular expressions to search for specific types of information within the packets, such as passwords, IP addresses, and email addresses. The script also provides the option to filter the packets based on the source or destination IP. Additionally, the script writes the output to a log file.

Disclaimer
The use of this script should not be used without proper authorization and should not be used to perform unauthorized actions on any network or system. The user is responsible for any actions taken using this code.

Note
This code is for educational and research purposes only.
