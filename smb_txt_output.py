import pyshark

def extract_smb_packets(pcap_file):

    # Read the PCAP file
    cap = pyshark.FileCapture(pcap_file, display_filter='smb2')

    smb_packets = []

    for packet in cap:
        # Extract necessary metadata
        try:
            smb_layer = packet['SMB2']
            metadata = {
                'timestamp': packet.sniff_time,
                'source_ip': packet.ip.src,
                'destination_ip': packet.ip.dst,
                'source_port': packet.tcp.srcport,
                'destination_port': packet.tcp.dstport,
                'command': smb_layer.cmd,
                'file_name': smb_layer.get_field_value('file_name') if 'file_name' in smb_layer.field_names else 'N/A',
                'file_size': smb_layer.get_field_value('file_size') if 'file_size' in smb_layer.field_names else 'N/A'
            }
            smb_packets.append(metadata)
        except AttributeError:
            continue  # Skip packets that don't have the expected SMB2 fields

    cap.close()
    return smb_packets

def save_metadata(smb_packets, output_file):
    with open(output_file, 'w') as f:
        for data in smb_packets:
            f.write(f"Timestamp: {data['timestamp']}\n")
            f.write(f"Source IP: {data['source_ip']}\n")
            f.write(f"Destination IP: {data['destination_ip']}\n")
            f.write(f"Source Port: {data['source_port']}\n")
            f.write(f"Destination Port: {data['destination_port']}\n")
            f.write(f"SMB Command: {data['command']}\n")
            f.write(f"File Name: {data['file_name']}\n")
            f.write(f"File Size: {data['file_size']}\n")
            f.write("\n")

# Path to the uploaded PCAP file
pcap_file = r'C:\\Users\\Username\\Downloads\\smb.pcap'

# Path to the outputted file
output_file = r'C:\\Users\Username\\Documents\\smb.txt'

smb_metadata = extract_smb_packets(pcap_file)
save_metadata(smb_metadata, output_file)

print(f"Extracted SMB metadata saved to {output_file}")