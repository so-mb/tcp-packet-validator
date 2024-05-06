import os
import re
import argparse


def ip_to_bytes(ip):
    return bytes(map(int, ip.split(".")))


def read_tcp_data(filename):
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        exit(1)
    except PermissionError:
        print(f"Error: Permission denied to read the file '{filename}'.")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading '{filename}': {e}")
        exit(1)


def create_pseudo_header(source_ip, dest_ip, tcp_length):
    return (
        ip_to_bytes(source_ip)
        + ip_to_bytes(dest_ip)
        + (0).to_bytes(1, byteorder="big")
        + (6).to_bytes(1, byteorder="big")
        + tcp_length.to_bytes(2, byteorder="big")
    )


def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = int.from_bytes(data[i : i + 2], "big")
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def validate_tcp_checksum(addr_file, data_file):
    try:
        with open(addr_file, "r") as f:
            source_ip, dest_ip = f.read().strip().split()
    except FileNotFoundError:
        print(f"Error: The file '{addr_file}' was not found.")
        exit(1)
    except ValueError:
        print(f"Error: The file '{addr_file}' does not contain valid IP addresses.")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading '{addr_file}': {e}")
        exit(1)

    tcp_data = read_tcp_data(data_file)
    if len(tcp_data) < 18:
        print(f"Error: The TCP data in '{data_file}' is too short to contain a valid checksum.")
        return "FAIL"

    tcp_length = len(tcp_data)
    pseudo_header = create_pseudo_header(source_ip, dest_ip, tcp_length)

    try:
        original_checksum = int.from_bytes(tcp_data[16:18], "big")
        tcp_zero_checksum = tcp_data[:16] + b"\x00\x00" + tcp_data[18:]
    except IndexError:
        print(f"Error: The TCP data in '{data_file}' is too short to contain a valid checksum.")
        return "FAIL"

    checksum_data = pseudo_header + tcp_zero_checksum
    computed_checksum = calculate_checksum(checksum_data)

    return "PASS" if computed_checksum == original_checksum else "FAIL"


def setup_cli():
    parser = argparse.ArgumentParser(description="TCP Packet Validator", add_help=True)
    parser.add_argument('-a', '--addr-file', type=str, help='Specify the path to the TCP addresses file.')
    parser.add_argument('-d', '--data-file', type=str, help='Specify the path to the TCP data file.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display verbose output including file names and results.')
    parser.add_argument('-u', '--usage', action='store_true', help='Show usage information and exit.')

    return parser


def print_usage():
    usage_text = """
TCP Packet Validator
(v1.0, https://github.com/so-mb/tcp-packet-validator)

Usage:
  python tcp_validator.py --help                            # Show help message and exit.
  python tcp_validator.py                                   # Run with default behavior of validating all files in the 'packets' directory.
  python tcp_validator.py -a <addr_file> -d <data_file>     # Specify address and data files.
  python tcp_validator.py --verbose                         # Display verbose output including file names and results.

Options:
  -a, --addr-file <file>  Specify the path to the TCP addresses file.
  -d, --data-file <file>  Specify the path to the TCP data file.
  -v, --verbose           Display verbose output including file names and results.
  -u, --usage             Show this usage information and exit.

For more information on this project, visit: https://beej.us/guide/bgnet0/html/#project-validating-a-tcp-packet 
"""
    print(usage_text)
    exit(0)


def numeric_sort(file):
    # Extract numbers from the filename and converts them to integers for sorting
    numbers = re.findall(r'\d+', file)
    return int(numbers[0]) if numbers else None


def default_validation(verbose=False):
    # List all files in the 'packets' directory
    files = os.listdir('./packets')
    addr_files = sorted([f for f in files if f.startswith('tcp_addrs_') and f.endswith('.txt')], key=numeric_sort)
    data_files = sorted([f for f in files if f.startswith('tcp_data_') and f.endswith('.dat')], key=numeric_sort)

    results = []
    # Assumes that for every addr file there is a corresponding data file
    for addr_file, data_file in zip(addr_files, data_files):
        full_addr_path = os.path.join('./packets', addr_file)
        full_data_path = os.path.join('./packets', data_file)
        result = validate_tcp_checksum(full_addr_path, full_data_path)
        results.append((full_addr_path, full_data_path, result))
    
    for addr_file, data_file, result in results:
        if verbose:
            print(f"{addr_file} and {data_file} -> {result}")
        else:
            print(result)


def main():
    parser = setup_cli()
    args = parser.parse_args()

    # Check if the --usage flag was used
    if args.usage:
        print_usage()
    
    # If the user specifies both files, validate those; otherwise, run the default validation
    if args.addr_file and args.data_file:
        result = validate_tcp_checksum(args.addr_file, args.data_file)
        if args.verbose:
            print(f"{args.addr_file} and {args.data_file} -> {result}")
        else:
            print(result)
    elif args.addr_file or args.data_file:
        parser.error("Both ADDR_FILE and DATA_FILE must be provided together. Check --usage for more information.")
    else:
        default_validation(args.verbose)


if __name__ == "__main__":
    main()
