# ZipVault Auditor

**ZipVault Auditor** is a Python-based project that allows users to audit and analyze password-protected zip files. It automatically decrypts zip files (using a password list), extracts their contents, checks the files for malicious content via VirusTotal, searches for specific keywords and emails within text and PDF files, and generates detailed reports on file integrity and keyword analysis.

## Features

- **Password Cracking**: Attempts to unlock password-protected zip files using a provided list of potential passwords.
- **SHA-256 Checksum Generation**: Calculates secure hash values for extracted files to verify their integrity.
- **VirusTotal API Integration**: Queries VirusTotal to check the security status of files by their checksums.
- **Keyword and Email Search**: Scans `.txt` and `.pdf` files for keywords such as "PESEL," "password," and extracts unique email addresses.
- **Report Generation**: Creates a comprehensive report containing file checksums, VirusTotal analysis results, keyword counts, and emails found.
- **Password-Protected Output**: Creates a final password-protected zip file containing the original files, the generated report, and the report’s checksum.

## Technologies Used

- **Python**: The primary programming language used for scripting and automation.
- **Zipfile**: For handling standard zip files, including extraction and listing.
- **Pyzipper**: Used for working with AES-encrypted zip files, including password-protection of the final output.
- **hashlib**: Generates SHA-256 checksums for file integrity verification.
- **requests**: Handles API requests to VirusTotal for file security analysis.
- **re (Regular Expressions)**: Used to search for keywords and extract unique emails from text files.
- **PyPDF2**: For extracting text content from PDF files to search for keywords.
- **logging**: Provides a detailed logging mechanism for process tracking and debugging.
- **shutil**: Handles file operations, including directory creation and deletion.
