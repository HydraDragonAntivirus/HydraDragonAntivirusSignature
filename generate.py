import os
import subprocess
import logging
import nltk
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

# Function to extract meaningful words from a decompiled file
def extract_meaningful_words(file_path):
    try:
        # Load the decompiled output file with UTF-8 encoding
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            code = file.read()

        # Tokenize the code into words
        words = nltk.word_tokenize(code)

        # Filter out non-alphanumeric words
        meaningful_words = [word for word in words if word.isalpha()]

        return meaningful_words
    except Exception as e:
        logging.error(f"Error extracting words from {file_path}: {e}")
        return []

# Function to calculate cosine similarity between two sets of words
def calculate_similarity(set1, set2):
    vectorizer = CountVectorizer().fit_transform([' '.join(set1), ' '.join(set2)])
    similarity_matrix = cosine_similarity(vectorizer)
    return similarity_matrix[0][1]  # Similarity between the two sets

# Function to compare data (malicious and benign) and calculate their similarity
def compare_data(malicious_data, benign_data):
    malicious_words = extract_meaningful_words(malicious_data)
    benign_words = extract_meaningful_words(benign_data)

    # Calculate the similarity between malicious and benign data
    similarity = calculate_similarity(malicious_words, benign_words)
    return similarity

# Function to extract and process the benign and malicious data
def process_benign_and_malicious_data():
    # Process benign data (data2)
    benign_data_files = [os.path.join(data_benign_dir, f) for f in os.listdir(data_benign_dir) if os.path.isfile(os.path.join(data_benign_dir, f))]
    malicious_data_files = [os.path.join(data_malicious_dir, f) for f in os.listdir(data_malicious_dir) if os.path.isfile(os.path.join(data_malicious_dir, f))]

    benign_words = []
    malicious_words = []

    # Decompile and extract words from the benign data
    for file_path in benign_data_files:
        logging.info(f"Processing benign file: {file_path}")
        decompile_file(file_path)
        extracted_words = extract_meaningful_words(file_path)
        benign_words.extend(extracted_words)

    # Decompile and extract words from the malicious data
    for file_path in malicious_data_files:
        logging.info(f"Processing malicious file: {file_path}")
        decompile_file(file_path)
        extracted_words = extract_meaningful_words(file_path)
        malicious_words.extend(extracted_words)

    return benign_words, malicious_words

# Function to analyze unknown files after processing benign and malicious data
def analyze_unknown_files(benign_words, malicious_words):
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

            # Calculate baseline similarity between benign and malicious data
            baseline_similarity = calculate_similarity(malicious_words, benign_words)
            logging.info(f"Baseline similarity between malicious and benign data: {baseline_similarity}")

            # Define similarity thresholds
            malicious_threshold = 0.86
            benign_threshold = 0.9

            # Analyze test files without blocking
            for file_path in files_to_analyze:
                logging.info(f"Analyzing unknown file: {file_path}")
                unknown_data = extract_meaningful_words(file_path)

                # Compare with baseline (malicious and benign data)
                malicious_similarity = calculate_similarity(unknown_data, malicious_words)
                benign_similarity = calculate_similarity(unknown_data, benign_words)

                logging.info(f"Similarity with malicious data: {malicious_similarity}")
                logging.info(f"Similarity with benign data: {benign_similarity}")

                # Classification based on thresholds
                if malicious_similarity >= malicious_threshold:
                    logging.info(f"{file_path} is classified as Malicious.")
                elif benign_similarity >= benign_threshold:
                    logging.info(f"{file_path} is classified as Benign.")
                else:
                    logging.info(f"{file_path} is Uncertain.")
    except Exception as e:
        logging.error(f"Error analyzing unknown files: {e}")

# Main function to start the analysis
def main():
    start_time = time.time()

    # Step 1: Process benign and malicious data
    logging.info("Processing benign and malicious data...")
    benign_words, malicious_words = process_benign_and_malicious_data()

    # Step 2: Analyze unknown files
    logging.info("Analyzing unknown files in the test folder...")
    analyze_unknown_files(benign_words, malicious_words)

    end_time = time.time()
    logging.info(f"Analysis completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
