# TCP Packet Validator

The TCP Packet Validator is a Python-based tool that checks the integrity of TCP packets by validating their checksums. It ensures that TCP packets have not been corrupted during transit by comparing computed checksums against those embedded within the packets themselves. This tool can handle predefined data sets or user-specified files and supports both command-line arguments and a verbose output mode for detailed inspection.


## Features
- Validates the checksum of TCP packets to ensure data integrity.
- Supports processing of predefined TCP packet data from the 'packets' directory.
- Allows users to specify custom address and data files for validation.
- Offers verbose output to detail the files processed and the results (PASS/FAIL).


## Requirements
- Python 3.x

## Usage
For a quick start, run the following command to display the usage instructions:
````
python tcp_validator.py --usage
````


## Structure
- **````tcp_validator.py````** -  The main Python script containing the logic for validating TCP packet checksums.
- **````packets/````** - Default directory containing sample TCP data files for validation.


## Additional Information
For more detailed information about TCP packet structure and validation techniques, visit [Beej's Guide to Network Programming](https://beej.us/guide/bgnet0/html/#project-validating-a-tcp-packet).
