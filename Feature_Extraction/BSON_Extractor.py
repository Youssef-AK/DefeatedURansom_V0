import os
import csv
import bson
import binascii

def decode_argument(arg):
    if isinstance(arg, bytes):
        try:
            # Try to decode as UTF-8
            return arg.decode('utf-8')
        except UnicodeDecodeError:
            # If decoding fails, display hexadecimal representation
            return f'hex:{binascii.hexlify(arg).decode("utf-8")}'

    return arg

def read_bson_file(bson_file_path):
    try:
        with open(bson_file_path, 'rb') as f:
            # Decode BSON data
            bson_data = bson.decode_all(f.read())

            # Handle binary data in the args
            for entry in bson_data:
                args = entry.get('args', [])
                decoded_args = [decode_argument(arg) for arg in args]
                entry['args'] = decoded_args

            return bson_data  # Return the list of BSON entries

    except bson.errors.BSONError as e:
        print(f"Error decoding BSON in file {bson_file_path}: {e}")
        return None

def extract_features_from_bson(entry):
    features = {}
    features['I'] = entry.get('I', '')
    features['T'] = entry.get('T', '')
    features['t'] = entry.get('t', '')
    features['h'] = entry.get('h', '')

    name = entry.get('name', '')
    args = entry.get('args', [])

    features['entry_name'] = name
    features['num_args'] = len(args)

    for i, arg in enumerate(args, start=1):
        features[f'arg_{i}'] = arg

    return features

def extract_and_write_features(main_directory, output_csv_dir):
    # Walk through the main directory tree
    for root, dirs, files in os.walk(main_directory):
        if "logs" in dirs:
            logs_directory = os.path.join(root, "logs")
            all_features = []  # List to store features for all BSON entries in the sample

            for file in os.listdir(logs_directory):
                if file.endswith(".bson"):
                    file_path = os.path.join(logs_directory, file)

                    # Read BSON entries from the file
                    bson_entries = read_bson_file(file_path)

                    # Check if read_bson_file returned valid entries
                    if bson_entries:
                        # Extract features for each entry
                        for entry in bson_entries:
                            entry_features = extract_features_from_bson(entry)
                            all_features.append(entry_features)

            # Create a unique CSV file for each sample
            family_name = os.path.basename(os.path.dirname(root))                
            sample_name = os.path.basename(root)
            output_csv_path = os.path.join(output_csv_dir, f"{family_name}_{sample_name}_BSONs.csv")

            # Write features to CSV with utf-8 encoding
            with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
                fieldnames = ['I', 'T', 't', 'h', 'entry_name', 'num_args'] + [f'arg_{i}' for i in range(1, 20)]  # Update 11 to the maximum expected number of args
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                
                # Write headers
                writer.writeheader()

                # Write data
                writer.writerows(all_features)

            print(f"BSON features stored in: {output_csv_path}")

# Example usage:
main_directory = "F:\\Ransom_samples"
output_csv_dir = "F:\\Analysis_Results\\Ransom_Samples_BSONs"
extract_and_write_features(main_directory, output_csv_dir)
