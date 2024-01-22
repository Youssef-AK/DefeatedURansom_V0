import json
import csv
import os

def explore_metadata(files_json_path, output_csv_path):
    # Initialize lists to store metadata
    file_paths = []
    file_pids = []
    file_filepaths = []

    # Read the files.json file line by line
    with open(files_json_path, 'r') as f:
        for line in f:
            try:
                # Parse each line as JSON
                file_data = json.loads(line)

                # Extract metadata
                file_paths.append(file_data['path'])
                file_pids.append(file_data.get('pids', []))  # Handle missing pids
                file_filepaths.append(file_data['filepath'] if file_data['filepath'] is not None else 'Unknown')  # Handle null filepath

            except json.JSONDecodeError:
                print(f"Ignoring invalid JSON on line: {line}")

    # Display metadata
    print("File Paths:")
    print(file_paths)

    print("\nFile Pids:")
    print(file_pids)

    print("\nFile Filepaths:")
    print(file_filepaths)

    # Save metadata to CSV
    with open(output_csv_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['File Paths', 'File Pids', 'File Filepaths'])
        csv_writer.writerows(zip(file_paths, file_pids, file_filepaths))

    print(f"\nMetadata saved to {output_csv_path}")

    # Return metadata for further use if needed
    return {
        'file_paths': file_paths,
        'file_pids': file_pids,
        'file_filepaths': file_filepaths
    }

def process_samples(root_directory, output_directory):
    # Iterate over all subdirectories in the root_directory
    for subdir, dirs, files in os.walk(root_directory):
        for file in files:
            # Check if the file is named 'files.json'
            if file == 'files.json':
                files_json_path = os.path.join(subdir, file)
                
                # Create a unique output CSV name based on the directory structure
                relative_path = os.path.relpath(files_json_path, root_directory)
                output_csv_name = os.path.splitext(relative_path.replace(os.path.sep, '_'))[0] + '_metadata.csv'
                output_csv_path = os.path.join(output_directory, output_csv_name)

                # Explore metadata and save to CSV
                metadata = explore_metadata(files_json_path, output_csv_path)

                # Further analysis or processing can be done with the extracted metadata
                # For example, you might want to handle missing pids or null filepaths differently.
                # You can also filter, clean, or transform the data based on your project requirements.

if __name__ == "__main__":
    # Specify the root directory where ransomware samples are stored
    root_directory = 'F:\\Ransom_samples'

    # Specify the output directory for CSV files
    output_directory = 'F:\Analysis_Results\Files_outputs'

    # Create the output directory if it doesn't exist
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Process all ransomware samples
    process_samples(root_directory, output_directory)

