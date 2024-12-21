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

# Function to extract meaningful words from a decompiled file (minimum 4 characters, UTF-8)
def extract_meaningful_words(file_path):
    try:
        # Load the decompiled output file with UTF-8 encoding
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            code = file.read()

        # Tokenize the code into words
        words = nltk.word_tokenize(code)

        # Filter out non-alphanumeric words and words with less than 4 characters
        meaningful_words = [word for word in words if word.isalpha() and len(word) >= 4]

        # Filter out any non-UTF-8 characters
        meaningful_words = [word for word in meaningful_words if is_utf8(word)]

        return meaningful_words
    except Exception as e:
        logging.error(f"Error extracting words from {file_path}: {e}")
        return []

# Function to check if a word is valid UTF-8
def is_utf8(text):
    try:
        text.encode('utf-8')
        return True
    except UnicodeEncodeError:
        return False

# Function to calculate cosine similarity between two sets of words
def calculate_similarity(set1, set2):
    vectorizer = CountVectorizer().fit_transform([' '.join(set1), ' '.join(set2)])
    similarity_matrix = cosine_similarity(vectorizer)
    return similarity_matrix[0][1]  # Similarity between the two sets

# Function to save the generic signatures to a file
def save_signatures(signatures, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for signature in signatures:
                file.write(f"{signature}\n")
        logging.info(f"Signatures saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving signatures: {e}")

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

# Main function to start the analysis
def main():
    start_time = time.time()

    # Step 1: Process benign and malicious data
    logging.info("Processing benign and malicious data...")
    benign_words, malicious_words = process_benign_and_malicious_data()

    # Step 2: Save signatures
    logging.info("Saving malicious and benign signatures...")
    save_signatures(malicious_words, 'malicious_signatures.txt')
    save_signatures(benign_words, 'benign_signatures.txt')

    end_time = time.time()
    logging.info(f"Analysis completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
