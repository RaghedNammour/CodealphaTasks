from scapy.all import sniff, IP, TCP
import csv

# Function to process each captured packet
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dest_port = tcp_layer.dport
        seq_num = tcp_layer.seq
        ack_num = tcp_layer.ack
        flags = tcp_layer.flags

        # Extract payload if available
        payload = bytes(packet[TCP].payload)
        if payload:
            try:
                decoded_payload = payload.decode('utf-8', errors='replace')  # Replace problematic chars
            except:
                decoded_payload = "Non-decodable data"
        else:
            decoded_payload = "No payload"

        # Display packet info in terminal
        print(f"IP Packet - Source: {src_ip}:{src_port}, Destination: {dest_ip}:{dest_port}")
        print(f"Sequence: {seq_num}, Acknowledgment: {ack_num}, Flags: {flags}")
        print(f"Payload: {decoded_payload.encode('ascii', errors='replace').decode()}")
        print('-' * 60)

        # Save to CSV
        with open('packets_log.csv', mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow([src_ip, dest_ip, src_port, dest_port, seq_num, ack_num, flags, decoded_payload])


# Setup CSV logging with headers
with open('packets_log.csv', mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(['Source IP', 'Destination IP', 'Source Port', 'Destination Port',
                      'Sequence Number', 'Acknowledgment Number', 'Flags', 'Payload'])

# Start packet capture (filtering for TCP traffic only)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="tcp", prn=process_packet, store=False)
