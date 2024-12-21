import os
import subprocess
import logging
import nltk
import re
from concurrent.futures import ThreadPoolExecutor
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import time
import sys

# Ensure NLTK resources are available
nltk.download('punkt')
nltk.download('words')

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Directories
script_dir = os.getcwd()
ghidra_scripts_dir = os.path.join(script_dir, 'scripts')
ghidra_logs_dir = os.path.join(script_dir, 'ghidra_logs')
test_dir = os.path.join(script_dir, 'test')
data_malicious_dir = os.path.join(script_dir, 'datamaliciousorder')
data_benign_dir = os.path.join(script_dir, 'data2')

# Define log file paths
console_log_file = os.path.join(script_dir, 'console_log.txt')
stdin_log_file = os.path.join(script_dir, 'stdin_log.txt')

# Redirect stdout and stderr to the console log file with UTF-8 encoding
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="replace")
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="replace")

# Redirect stdin to the log file with UTF-8 encoding
sys.stdin = open(stdin_log_file, "w+", encoding="utf-8", errors="replace")

# Function to decompile using Ghidra
def decompile_file(file_path, project_name='temporary'):
    try:
        logging.info(f"Decompiling file: {file_path}")

        # Path to Ghidra's analyzeHeadless.bat
        analyze_headless_path = os.path.join(script_dir, 'ghidra', 'support', 'analyzeHeadless.bat')
        project_location = os.path.join(script_dir, 'ghidra_projects')

        # Ensure the project location exists
        if not os.path.exists(project_location):
            os.makedirs(project_location)

        # Build the command to run analyzeHeadless.bat
        command = [
            analyze_headless_path,
            project_location,
            project_name,
            '-import', file_path,
            '-postScript', 'DecompileAndSave.java',
            '-scriptPath', ghidra_scripts_dir,
            '-log', os.path.join(ghidra_logs_dir, 'analyze.log')
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)

        # Check and log the results
        if result.returncode == 0:
            logging.info(f"Decompilation completed successfully for file: {file_path}")
        else:
            logging.error(f"Decompilation failed for file: {file_path}.")
            logging.error(f"Return code: {result.returncode}")
            logging.error(f"Error output: {result.stderr}")
            logging.error(f"Standard output: {result.stdout}")
    except Exception as e:
        logging.error(f"An error occurred during decompilation: {e}")

# Function to extract meaningful words or patterns (e.g., function names, string literals) from a decompiled file
def extract_code_patterns(file_path):
    try:
        # Load the decompiled output file with UTF-8 encoding
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            code = file.read()

        # Extract function names using regex (this is a simple example, refine it based on actual Ghidra output)
        function_names = re.findall(r'\b\w+\b', code)
        
        # Extract string literals or suspicious patterns (example)
        string_literals = re.findall(r'"([^"]*)"', code)

        return function_names + string_literals
    except Exception as e:
        logging.error(f"Error extracting patterns from {file_path}: {e}")
        return []

# Function to identify frequent patterns in a list of files
def find_frequent_patterns(files, threshold=3):
    pattern_count = {}
    
    for file_path in files:
        patterns = extract_code_patterns(file_path)
        for pattern in patterns:
            pattern_count[pattern] = pattern_count.get(pattern, 0) + 1

    # Filter patterns that occur more than the threshold
    frequent_patterns = {k: v for k, v in pattern_count.items() if v > threshold}
    return frequent_patterns

# Function to extract and process benign and malicious data
def process_benign_and_malicious_data():
    # Process benign data (data2)
    benign_data_files = [os.path.join(data_benign_dir, f) for f in os.listdir(data_benign_dir) if os.path.isfile(os.path.join(data_benign_dir, f))]
    malicious_data_files = [os.path.join(data_malicious_dir, f) for f in os.listdir(data_malicious_dir) if os.path.isfile(os.path.join(data_malicious_dir, f))]

    benign_patterns = []
    malicious_patterns = []

    # Decompile and extract patterns from the benign data
    for file_path in benign_data_files:
        logging.info(f"Processing benign file: {file_path}")
        decompile_file(file_path)
        extracted_patterns = extract_code_patterns(file_path)
        benign_patterns.extend(extracted_patterns)

    # Decompile and extract patterns from the malicious data
    for file_path in malicious_data_files:
        logging.info(f"Processing malicious file: {file_path}")
        decompile_file(file_path)
        extracted_patterns = extract_code_patterns(file_path)
        malicious_patterns.extend(extracted_patterns)

    return benign_patterns, malicious_patterns

# Function to save the generic signatures to a file
def save_signatures(signatures, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for signature in signatures:
                file.write(f"{signature}\n")
        logging.info(f"Signatures saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving signatures: {e}")

# Function to analyze unknown files after processing benign and malicious data
def analyze_unknown_files(benign_patterns, malicious_patterns):
    try:
        files_to_analyze = [os.path.join(test_dir, f) for f in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, f))]
        
        # Create a ThreadPoolExecutor with as many workers as there are CPU cores
        max_workers = os.cpu_count() or 20  # Use the number of CPU cores or default to 20
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            logging.info(f"Using up to {max_workers} threads for analysis.")
            
            # Submit all decompilation tasks simultaneously
            futures = {executor.submit(decompile_file, file_path): file_path for file_path in files_to_analyze}

            # Continuously process completed futures
            for future in futures:
                try:
                    future.result()  # Retrieve the result or raise any exception that occurred
                except Exception as e:
                    logging.error(f"Error processing file {futures[future]}: {e}")

            # Analyze test files
            for file_path in files_to_analyze:
                logging.info(f"Analyzing unknown file: {file_path}")
                unknown_data = extract_code_patterns(file_path)

                # Compare with malicious patterns
                for pattern in malicious_patterns:
                    if pattern in unknown_data:
                        logging.info(f"{file_path} contains suspicious pattern: {pattern}")
                        break

    except Exception as e:
        logging.error(f"Error analyzing unknown files: {e}")

# Main function to start the analysis
def main():
    start_time = time.time()

    # Step 1: Process benign and malicious data
    logging.info("Processing benign and malicious data...")
    benign_patterns, malicious_patterns = process_benign_and_malicious_data()

    # Step 2: Identify frequent malicious patterns
    logging.info("Identifying frequent malicious patterns...")
    malicious_signatures = find_frequent_patterns([os.path.join(data_malicious_dir, f) for f in os.listdir(data_malicious_dir)])
    benign_signatures = find_frequent_patterns([os.path.join(data_benign_dir, f) for f in os.listdir(data_benign_dir)])

    # Step 3: Save generic signatures
    logging.info("Saving generic signatures...")
    save_signatures(malicious_signatures, 'malicious_signatures.txt')
    save_signatures(benign_signatures, 'benign_signatures.txt')

    # Step 4: Analyze unknown files
    logging.info("Analyzing unknown files...")
    analyze_unknown_files(benign_signatures, malicious_signatures)

    end_time = time.time()
    logging.info(f"Analysis completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
