# Required Modules
import dpkt
import math
import socket
import csv
from collections import Counter
import statistics


# Function to extract features from pcap file
def extract_pcap_features(file_path):
    """
    Extracts a comprehensive set of features from a PCAP file that can be used to detect ransomware and identify threat actors.

    Args:
        file_path: The path to the PCAP file.

    Returns:
        A dictionary of features.
    """

    # Open the PCAP file.
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # Initialize the features dictionary.
        features = {}

        # Initialize counters and lists.
        packets = []
        tcp_packets = []
        udp_packets = []
        ipv4_packets = []
        ipv6_packets = []
        src_ports = []
        dst_ports = []
        flows = {}
        http_packets = []
        https_packets = []
        dns_packets = []
        interarrival_times = []
        payload_lengths = []
        src_ips = []
        dst_ips = []
        file_types = []
        entropy_values = []

        # Initialize counters and lists.
        timestamps = []
        tcp = None
        udp = None

        # Iterate over packets.
        for timestamp, buf in pcap:
            # Parse the Ethernet frame (buf) into an Ethernet object (eth).
            eth = dpkt.ethernet.Ethernet(buf)

            # Check if this is an IP packet.
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data  # This is an IP packet.

                # Add to IP packets list.
                packets.append(ip)

                # Check for TCP.
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    tcp_packets.append(tcp)
                    src_ports.append(tcp.sport)
                    dst_ports.append(tcp.dport)

                    # Check for HTTP.
                    if tcp.dport == 80 or tcp.sport == 80:
                        http_packets.append(tcp)
                        try:
                            http = dpkt.http.Request(tcp.data)
                            file_types.append(http.uri.split('/')[-1])
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            pass

                    # Check for HTTPS.
                    if tcp.dport == 443 or tcp.sport == 443:
                        https_packets.append(tcp)

                    # Check for flows.
                    if tcp:
                        flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
                        if flow_key in flows:
                            flows[flow_key] += 1
                        else:
                            flows[flow_key] = 1

                # Check for UDP.
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    udp_packets.append(udp)
                    src_ports.append(udp.sport)
                    dst_ports.append(udp.dport)

                    # Check for DNS.
                    if udp and (udp.dport == 53 or udp.sport == 53):
                        dns_packets.append(udp)

                # Check for IPv4.
                if isinstance(ip, dpkt.ip.IP):
                    ipv4_packets.append(ip)
                    src_ips.append(socket.inet_ntoa(ip.src))
                    dst_ips.append(socket.inet_ntoa(ip.dst))

                # Check for IPv6.
                elif isinstance(ip, dpkt.ip6.IP6):
                    ipv6_packets.append(ip)
                    src_ips.append(socket.inet_ntop(socket.AF_INET6, ip.src))
                    dst_ips.append(socket.inet_ntop(socket.AF_INET6, ip.dst))

                # Calculate interarrival times.
                if len(timestamps) > 0:
                    interarrival_times.append(timestamp - timestamps[-1])

                # Calculate payload lengths.
                payload_lengths.append(len(ip.data))

                # Calculate flows.
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport

                    if (ip.src, ip.dst, src_port, dst_port) in flows:
                        flows[(ip.src, ip.dst, src_port, dst_port)] += 1
                    else:
                        flows[(ip.src, ip.dst, src_port, dst_port)] = 1


               # Calculate entropy of payload
                entropy_values = [calculate_entropy(p.data) for p in packets]

                # Calculate average entropy using statistics.mean
                average_entropy = statistics.mean(entropy_values) if entropy_values else 0  
                max_entropy = max(entropy_values) if entropy_values else 0


        # Extract basic features.
        features["num_packets"] = len(packets)
        features["avg_packet_len"] = sum(payload_lengths) / len(payload_lengths) if len(payload_lengths) > 0 else 0

        # Extract transport layer features.
        features["num_tcp_packets"] = len(tcp_packets)
        features["num_udp_packets"] = len(udp_packets)

        # Extract IP layer features.
        features["num_ipv4_packets"] = len(ipv4_packets)
        features["num_ipv6_packets"] = len(ipv6_packets)

        # Extract port features.
        features["num_unique_src_ports"] = len(set(src_ports))
        features["num_unique_dst_ports"] = len(set(dst_ports))

        # Extract flow features.
        features["num_flows"] = len(flows)
        features["avg_flow_size"] = sum(flows.values()) / len(flows) if len(flows) > 0 else 0

        # Extract payload features.
        features["num_http_packets"] = len(http_packets)
        features["num_https_packets"] = len(https_packets)
        features["num_dns_packets"] = len(dns_packets)

        # Extract timing features.
        features["min_interarrival_time"] = min(interarrival_times) if len(interarrival_times) > 0 else 0
        features["max_interarrival_time"] = max(interarrival_times) if len(interarrival_times) > 0 else 0
        features["avg_interarrival_time"] = sum(interarrival_times) / len(interarrival_times) if len(interarrival_times) > 0 else 0

        # Extract source and destination IP addresses
        features["source_ip"] = src_ips[0] if len(src_ips) > 0 else None
        features["destination_ip"] = dst_ips[0] if len(dst_ips) > 0 else None

        # Extract file type features
        features["file_types"] = file_types

        # Add summary statistics of entropy.
        features["average_payload_entropy"] = average_entropy
        features["max_payload_entropy"] = max_entropy

        return features




def calculate_entropy(data):
    """
    Calculates the entropy of a string.

    Args:
        data: The string to calculate the entropy of.

    Returns:
        The entropy of the string.
    """

    if len(data) == 0:
        return 0

    # Create a frequency table using collections.Counter
    freq_table = Counter(data)

    # Calculate the entropy
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in freq_table.values())

    return entropy 




# Save results
def save_features_to_csv(features, file_path):
    """
    Saves the features to a CSV file.

    Args:
        features: The features to save.
        file_path: The path to the CSV file.
    """

    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        # Write the header row.
        csv_writer.writerow(features.keys())

        # Write the data rows.
        data_row = list(features.values())
        csv_writer.writerow(data_row)




'''

And here's an example of how to use the `extract_pcap_features()` and `save_features_to_csv()` functions:

'''

# # Extract the features from a PCAP file.
# features = extract_pcap_features('dump.pcap')

# # Save the features to a CSV file.
# save_features_to_csv(features, 'Output/pcap_features.csv')

# # Print the features.
# print("Extracted PCAP Features:\n")
# for feature, value in features.items():
#     print(f'{feature}: {value}')