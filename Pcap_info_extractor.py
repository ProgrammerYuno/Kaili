import re
from scapy.all import *
import binascii
import OpenSSL
import os
import argparse

# Disclaimer:

#THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
#REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
#INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
#LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
#OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#PERFORMANCE OF THIS SOFTWARE.

#Additional note:

# This code is for educational and research purposes only.
# It should not be used without proper authorization and should not be used to perform unauthorized actions on any network or system.
# The user is responsible for any actions taken using this code.

parser = argparse.ArgumentParser(description='pcap_info_extractor.py')
parser.add_argument('pcapfile', help='the pcap file')
parser.add_argument('-s', '--src', default='', help='filter on source IP')
parser.add_argument('-d', '--dst', default='', help='filter on destination IP')
parser.add_argument('-o', '--output', help='output file')
args = parser.parse_args()

# Function to handle errors
def handle_error(e, error_msg):
    print(error_msg)
    print(e)
    exit()

try:
    # Read in the Wireshark capture file
    packets = rdpcap(args.pcapfile)
except FileNotFoundError as e:
    handle_error(e, "Error: Capture file not found.")
except Exception as e:
    handle_error(e, "Error: An error occurred while reading the capture file.")

# Regular expressions for matching various information
password_regex = re.compile(r"(?i)password[=:\s].*")
username_regex = re.compile(r"(?i)username[=:\s].*")
website_regex = re.compile(r"(?i)http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
ip_regex = re.compile(r"(?i)(\d{1,3}\.){3}\d{1,3}")
email_regex = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}")
mac_regex = re.compile(r"(?i)[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}")
hostname_regex = re.compile(r"(?i)[a-zA-Z0-9]+\.[a-zA-Z]{2,}")
file_name_regex = re.compile(r"(?i)[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}")

# Add filters
filter_src = args.src
filter_dst = args.dst

# Create a log file
with open("log.txt", "w") as f:
    # Iterate through each packet in the capture
    for packet in packets:
        # Check if the packet is a TCP packet
        if packet.haslayer(TCP) and (filter_src == "" or packet[IP].src == filter_src) and (filter_dst == "" or packet[IP].dst == filter_dst):
            # Check if the packet contains a payload (i.e. it's not just a header)
            if packet.payload:
                # Convert the packet payload to a string
                payload = str(binascii.hexlify(packet.payload))
                cipher = None
                # Add a list of supported encryption methods
                encryption_methods = ["TLSv1_2_METHOD", "TLSv1_1_METHOD", "TLSv1_METHOD"]

                # Iterate through each encryption
                # Iterate through each encryption method in the list
                for method in encryption_methods:
                    try:
                        cipher = getattr(OpenSSL.SSL, method)
                        bio = OpenSSL.SSL.MemoryBIO(binascii.unhexlify(payload))
                        ctx = OpenSSL.SSL.Context(cipher)
                        ctx.set_options(OpenSSL.SSL.OP_NO_TLSv1_2)
                        conn = OpenSSL.SSL.Connection(ctx, bio)
                        conn.set_connect_state()
                        conn.do_handshake()
                        payload = conn.recv(1024).decode("utf-8")
                        # If successful, break out of the loop
                        break
                    except Exception as e:
                        pass
                # Extract password if present
                password = password_regex.search(payload)
                if password:
                    print("Possible password found:", password.group())
                    f.write("Possible password found: " + password.group() + "\n")

                # Extract username if present
                username = username_regex.search(payload)
                if username:
                    print("Possible username found:", username.group())
                    f.write("Possible username found: " + username.group() + "\n")

                               # Extract website if present
                website = website_regex.search(payload)
                if website:
                    print("Possible website found:", website.group())
                    f.write("Possible website found: " + website.group() + "\n")

                # Extract IP if present
                ip = ip_regex.search(payload)
                if ip:
                    print("Possible IP found:", ip.group())
                    f.write("Possible IP found: " + ip.group() + "\n")

                # Extract email if present
                email = email_regex.search(payload)
                if email:
                    print("Possible email found:", email.group())
                    f.write("Possible email found: " + email.group() + "\n")

                # Extract MAC if present
                mac = mac_regex.search(payload)
                if mac:
                    print("Possible MAC found:", mac.group())
                    f.write("Possible MAC found: " + mac.group() + "\n")

                # Extract hostname if present
                hostname = hostname_regex.search(payload)
                if hostname:
                    print("Possible hostname found:", hostname.group())
                    f.write("Possible hostname found: " + hostname.group() + "\n")

                # Extract file name if present
                file_name = file_name_regex.search(payload)
                if file_name:
                    print("Possible file name found:", file_name.group())
                    f.write("Possible file name found: " + file_name.group() + "\n")
