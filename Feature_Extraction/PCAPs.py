import os
import csv
from Ransom_Pcap import extract_pcap_features, save_features_to_csv

def process_samples(base_directory, output_directory):
    for root, dirs, files in os.walk(base_directory):
        for file in files:
            if file.endswith(".pcap"):
                file_path = os.path.join(root, file)
                
                # Extract information from the directory structure
                ransomware_name, sample_id = root.split(os.path.sep)[-2:]
                
                # Naming convention for CSV file
                output_csv = os.path.join(output_directory, f"pcap_feats_{ransomware_name}_{sample_id}.csv")

                # Extract features
                features = extract_pcap_features(file_path)

                # Save features to CSV
                save_features_to_csv(features, output_csv)

if __name__ == "__main__":
    base_directory = r"F:\Ransom_samples"
    output_directory = r"F:\Analysis_Results\Ransom_Pcaps_output"

    # Process all samples
    process_samples(base_directory, output_directory)