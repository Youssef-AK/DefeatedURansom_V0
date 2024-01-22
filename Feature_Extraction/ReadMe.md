Feature extraction is a critical step in the process of analyzing network traffic data, especially when it comes to detecting and identifying potential cybersecurity threats such as ransomware attacks. This process involves transforming raw packet-level data from network captures (PCAP files) into a set of meaningful features that can be used for further analysis and threat detection.

The feature extraction script provided here is tailored for ransomware detection and threat actor identification. It leverages the dpkt library to parse PCAP files, extracting various features that offer insights into network behavior. These features include packet counts, payload lengths, transport layer protocols (TCP/UDP), source and destination IP addresses, port information, flow characteristics, HTTP and HTTPS activity, DNS queries, interarrival times, and more.

Additionally, the script calculates entropy for payload data, providing a measure of randomness and complexity within the network traffic. Entropy can be a valuable feature for identifying patterns associated with ransomware attacks.

The extracted features are saved in CSV format, making it easy to analyze the data using tools like spreadsheets or machine learning algorithms. The script is designed to be applied across multiple PCAP files, making it scalable for analyzing network traffic from various samples and potentially aiding in the identification of different ransomware families or threat actors.

This feature extraction tool aims to provide a starting point for cybersecurity analysts and researchers to gain insights into network traffic patterns, ultimately assisting in the detection and understanding of ransomware attacks.

Files_Extractor: 
* The "path" provides information about the location or name of the file, 
* "pids" provides information about process IDs associated with the file, 
* "filepath" gives the actual file path on the system.



