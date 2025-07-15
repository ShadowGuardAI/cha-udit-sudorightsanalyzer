#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
import yaml  # Added to handle YAML for potential future configuration

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes sudoers file for overly permissive or insecure sudo rights assignments.")

    # Add an argument for specifying the sudoers file path
    parser.add_argument("-f", "--sudoers_file",
                        help="Path to the sudoers file (default: /etc/sudoers)",
                        default="/etc/sudoers")

    # Add an argument for outputting to a file
    parser.add_argument("-o", "--output_file",
                        help="Path to the output file (optional)",
                        default=None)
    
    # Argument for enabling verbose output
    parser.add_argument("-v", "--verbose",
                        help="Enable verbose output",
                        action="store_true")


    return parser.parse_args()


def analyze_sudoers_file(sudoers_file_path):
    """
    Analyzes the sudoers file for potential security vulnerabilities.

    Args:
        sudoers_file_path (str): The path to the sudoers file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a potential vulnerability.
               Returns an empty list if no vulnerabilities are found or an error occurs.
    """
    vulnerabilities = []

    try:
        with open(sudoers_file_path, 'r') as f:
            sudoers_content = f.readlines()
    except FileNotFoundError:
        logging.error(f"Sudoers file not found: {sudoers_file_path}")
        print(f"Error: Sudoers file not found: {sudoers_file_path}")
        return vulnerabilities
    except PermissionError:
        logging.error(f"Permission denied to read sudoers file: {sudoers_file_path}")
        print(f"Error: Permission denied to read sudoers file: {sudoers_file_path}")
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error reading sudoers file: {e}")
        print(f"Error reading sudoers file: {e}")
        return vulnerabilities

    # Basic regex patterns for analysis
    ALL_PATTERN = r"ALL(\s*NOPASSWD:)?\s*ALL"  # Matches "ALL ALL" with optional NOPASSWD
    NOPASSWD_PATTERN = r"NOPASSWD:"  # Matches NOPASSWD
    
    for i, line in enumerate(sudoers_content):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Check for insecure ALL ALL configurations
        if "ALL=(ALL)" in line and not re.search(NOPASSWD_PATTERN, line):
             vulnerabilities.append({
                "line_number": i + 1,
                "description": "User/Group can run any command as root, consider restricting.",
                "line": line
            })
        if re.search(ALL_PATTERN, line):
            vulnerabilities.append({
                    "line_number": i + 1,
                    "description": "Insecure ALL ALL configuration found, consider restricting.",
                    "line": line
                })

        # Check for NOPASSWD for ALL commands (potential risk)
        if re.search(NOPASSWD_PATTERN, line) and "ALL=(ALL)" in line:
            vulnerabilities.append({
                "line_number": i + 1,
                "description": "NOPASSWD for all commands found, this poses a security risk.",
                "line": line
            })


    return vulnerabilities


def print_vulnerabilities(vulnerabilities, output_file=None, verbose=False):
    """
    Prints the identified vulnerabilities to the console or a file.

    Args:
        vulnerabilities (list): A list of vulnerability dictionaries.
        output_file (str, optional): Path to the output file. Defaults to None (prints to console).
        verbose (bool): Whether to print additional information. Defaults to False.
    """

    if not vulnerabilities:
        if verbose:
            print("No vulnerabilities found.")  #Only print when verbose
        return

    output = ""  # Accumulate output string for file writing

    for vulnerability in vulnerabilities:
        message = f"Line {vulnerability['line_number']}: {vulnerability['description']}\n  Line content: {vulnerability['line']}"
        if verbose:
            logging.warning(message) # also log the warnings
        output += message + "\n"

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"Vulnerabilities written to {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            print(f"Error writing to output file: {e}")
    else:
        print(output)


def main():
    """
    Main function to execute the sudoers file analysis.
    """
    args = setup_argparse()

    # Input validation for sudoers_file path
    if not os.path.isfile(args.sudoers_file):
        print(f"Error: Sudoers file not found: {args.sudoers_file}")
        logging.error(f"Sudoers file not found: {args.sudoers_file}")
        sys.exit(1)

    # Analyze the sudoers file
    vulnerabilities = analyze_sudoers_file(args.sudoers_file)

    # Print the vulnerabilities
    print_vulnerabilities(vulnerabilities, args.output_file, args.verbose)


if __name__ == "__main__":
    main()

#Example Usage:
# python cha-udit-SudoRightsAnalyzer.py -f /etc/sudoers
# python cha-udit-SudoRightsAnalyzer.py -f /etc/sudoers -o report.txt
# python cha-udit-SudoRightsAnalyzer.py -f /etc/sudoers -v
# python cha-udit-SudoRightsAnalyzer.py -f /etc/sudoers -o report.txt -v