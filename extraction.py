import sys
from scapy.all import *

def extract_executable(pcap_file, output_directory):
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if payload.startswith(b'MZ'): # Check if the payload is an executable
                with open(f"{output_directory}/extracted_executable.exe", "wb") as f:
                    f.write(payload)
                    print("Executable extracted successfully.")
                    break

if __name__ == "__main__":
    pcap_file = sys.argv[1]
    output_directory = sys.argv[2]
    extract_executable(pcap_file, extracted)
