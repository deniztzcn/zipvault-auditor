import os
import zipfile
import time
import hashlib
import requests
import re
import PyPDF2
import logging
import shutil
import pyzipper

# Check if the directory already exists
if os.path.exists("zipfile"):
    # If it exists, remove it and all its contents
    shutil.rmtree("zipfile")

# Now create the directory
os.mkdir("zipfile")

# Setup logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
        logging.FileHandler("zipfile/log.txt"),
        logging.StreamHandler()
    ])

# Function to get file path from user input
def get_file_path(message):
    file_path = input(message)
    logging.info(f"User provided file path: {file_path}")
    return file_path


# Function to check if a file is a valid zip file
def is_valid_zip(file_path):
    valid = zipfile.is_zipfile(file_path)
    logging.info(f"Checked if file is a valid zip: {valid}")
    return valid

# Function to read a list of passwords from a file
def read_password_list(password_file_path):
    with open(password_file_path, 'r') as file:
        passwords = [line.strip() for line in file]
    logging.info(f"Read {len(passwords)} passwords from file")
    return passwords


# Function to check if a zip file is password protected
def check_password_protected(zip_file):
    protected = any(zip_info.flag_bits & 0x1 for zip_info in zip_file.infolist())
    logging.info(f"Checked if zip file is password protected: {protected}")
    return protected

# Function to find the correct password and extract the zip file
def find_password_and_extract(zip_file, password_list):
    start_time = time.time()
    extract_to = os.path.splitext(zip_file.filename)[0]
    for password in password_list:
        try:
            zip_file.extractall(path=extract_to,pwd=password.encode())
            end_time = time.time()
            logging.info(f"Password found: {password}")
            logging.info(f"Time taken: {end_time - start_time} seconds")
            logging.info(f"Zip file extracted to: {extract_to} directory")
            return password
        except RuntimeError as e:
            if 'Bad password for file' in str(e):
                continue
            else:
                logging.error(f"An error occurred: {e}")
                raise e
    end_time = time.time()
    logging.warning("Password not found.")
    logging.info(f"Time taken: {end_time - start_time} seconds")


# Function to generate SHA-256 checksum for given file bytes
def generate_sha256_checksum(file_bytes):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    checksum = sha256_hash.hexdigest()
    logging.info(f"Generated SHA-256 checksum: {checksum}")
    return checksum


# Function to list files in a zip and generate their checksums
def list_files_and_hash(zip_file,password):
    files_hash = {}
    logging.info("Listing files in the zip file:")
    for file_info in zip_file.infolist():
        file_name = file_info.filename
        logging.info(f"Found file: {file_name}")
        with zip_file.open(file_name,pwd=password.encode()) as zip_ref:
            file_bytes = zip_ref.read()
            checksum = generate_sha256_checksum(file_bytes)
            files_hash[file_name] = checksum
            logging.info(f"File: {file_name}, Checksum: {checksum}")
    return files_hash


# Function to query VirusTotal API for a given hash value
def query_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code == 200:
        logging.info(f"VirusTotal query successful for hash: {hash_value}")
        return data
    else:
        logging.error(f"VirusTotal query failed with status code {response.status_code}: {data}")
        response.raise_for_status()


# Function to generate a report from VirusTotal API response
def report_virustotal_response(response_json):
    data = response_json.get('data', {})
    attributes = data.get('attributes', {})

    file_report = {
        'detection_ratio': f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/"
                           f"{attributes.get('last_analysis_stats', {}).get('harmless', 0) + attributes.get('last_analysis_stats', {}).get('malicious', 0) + attributes.get('last_analysis_stats', {}).get('suspicious', 0) + attributes.get('last_analysis_stats', {}).get('undetected', 0)}"
    }
    logging.info(f"VirusTotal report generated: {file_report}")
    return file_report


# Function to search for specific keywords and unique emails in file content
def search_keywords_in_file(file_content):
    keyword_counts = {
        'PESEL': len(re.findall(r'\bPESEL\b', file_content)),
        'password': len(re.findall(r'\bpassword\b', file_content))
    }
    unique_emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', file_content)))
    return keyword_counts, unique_emails


# Function to analyze files in the zip for keywords and emails
def analyze_files(zip_file, password):
    keyword_summary = {}
    logging.info("Analyzing files for keywords and emails.")
    for file_info in zip_file.infolist():
        file_name = file_info.filename
        if file_name.endswith('.txt') or file_name.endswith('.pdf'):
            with zip_file.open(file_name, pwd=password.encode()) as zip_ref:
                if file_name.endswith('.txt'):
                    file_content = zip_ref.read().decode('utf-8')
                elif file_name.endswith('.pdf'):
                    reader = PyPDF2.PdfFileReader(zip_ref)
                    file_content = ''.join([reader.getPage(i).extract_text() for i in range(reader.getNumPages())])

                keyword_counts, unique_emails = search_keywords_in_file(file_content)
                keyword_summary[file_name] = {
                    'keyword_counts': keyword_counts,
                    'unique_emails': unique_emails
                }
                logging.info(
                    f"File analyzed: {file_name}, Keywords found: {keyword_counts}, Emails found: {unique_emails}")
    return keyword_summary


# Function to generate a comprehensive report of file checksums, VirusTotal results, and keyword analysis
def generate_report(files_hash, virustotal_reports, keyword_summary):
    report = ["FILE STATUS REPORT", "", "{:<30} {:<64} {:<}".format("File name", "checksum (sha-256)", "result")]

    for file_name, checksum in files_hash.items():
        virustotal_result = virustotal_reports.get(file_name, "No result")
        report.append("{:<30} {:<64} {:<}".format(file_name, checksum, str(virustotal_result)))

    report.append("")
    report.append("=" * 120)
    report.append("")
    report.append("KEYWORDS REPORT")
    report.append("")

    for file_name, summary in keyword_summary.items():
        report.append(file_name)
        report.append("")
        report.append("{:<20} {:<}".format("Keywords", "occurrence"))
        for keyword, count in summary['keyword_counts'].items():
            report.append("{:<20} {:<}".format(keyword.upper(), count))

        report.append("")
        report.append("Unique emails:")
        for email in summary['unique_emails']:
            report.append(email)
        report.append("")
    logging.info("Generated report.")
    return "\n".join(report)


# Function to create a password-protected zip file from a directory
def zip_directory_with_password(directory_path, zip_name):
    if not os.path.isdir(directory_path):
        logging.error(f"The directory {directory_path} does not exist.")
        return
    temp_zip_path = os.path.join(os.path.dirname(directory_path), f"{zip_name}.tmp")

    try:
        with pyzipper.AESZipFile(temp_zip_path, 'w', encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(b"P4$$w0rd!")
            for root, _, files in os.walk(directory_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    relative_path = os.path.relpath(full_path, start=directory_path)
                    zf.write(full_path, relative_path)
                    logging.info(f"File added to new zip: {full_path}")

        shutil.move(temp_zip_path, zip_name)
        logging.info(f"Encrypted zip file created: {zip_name}")
    except Exception as e:
        logging.error(f"An error occurred while creating the zip file: {e}")
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
        raise e


# Main function to orchestrate the entire process
def main():
    new_zip_name = "result.zip"
    api_key = "4a884a669952c2faee125dc7a59d45c19edb10ab57c599fcd8ae7c72159df5a5"

    # Get the zip file path from the user
    file_path = get_file_path("Please enter the zip file path: ")

    # Check if the file exists
    if not os.path.exists(file_path):
        logging.error("The file does not exist. Please try again.")
        return

    # Check if the file is a valid zip file
    if not is_valid_zip(file_path):
        logging.error("The file is not a valid zip file. Please provide a .zip file.")
        return

    # Get the password file path from the user
    password_file = get_file_path("Please enter the password file:")

    # Check if the password file exists
    if not os.path.exists(password_file):
        logging.error("The password file does not exist. Please try again.")
        return

    with zipfile.ZipFile(file_path, 'r') as zip_file:
        # Check if the zip file is password protected
        if check_password_protected(zip_file):
            logging.info(f"{os.path.basename(zip_file.filename)} is password protected.")
            password_list = read_password_list(password_file)
            password = find_password_and_extract(zip_file, password_list)
            if password is None:
                logging.info("Password is not found")
                return
            files_hash = list_files_and_hash(zip_file, password)
            keywords = analyze_files(zip_file, password)
        else:
            logging.info("The zip file is not password protected.")
            extract_to = os.path.splitext(zip_file.filename)[0]
            zip_file.extractall(path=extract_to)
            logging.info(f"Zip file extracted to: {extract_to}")

    # Query VirusTotal for each file's checksum and generate a report
    virustotal_reports = {}
    for file in files_hash.keys():
        json_response = query_virustotal(files_hash[file], api_key)
        virustotal_reports[file] = report_virustotal_response(json_response)

    # Generate and write the report to a file
    report = generate_report(files_hash, virustotal_reports, keywords)
    with open("zipfile/report.txt", "w") as report_file:
        report_file.write(report)
    logging.info("Report written to report.txt")

    # Generate and write the SHA-256 checksum of the report to a file
    with open("zipfile/report.txt", "rb") as report_file:
        report_content = report_file.read()
        checksum = generate_sha256_checksum(report_content)
    with open("zipfile/hash.txt", "w") as hash_file:
        hash_file.write(checksum)
    logging.info("SHA-256 checksum written to hash.txt")

    # Create a password-protected zip file containing the logs and reports
    zip_directory_with_password("zipfile",new_zip_name)

if __name__ == "__main__":
    main()