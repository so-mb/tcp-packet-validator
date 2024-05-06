def ip_to_bytes(ip):
    return bytes(map(int, ip.split(".")))


def read_tcp_data(filename):
    with open(filename, "rb") as f:
        return f.read()


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
    with open(addr_file, "r") as f:
        source_ip, dest_ip = f.read().strip().split()

    tcp_data = read_tcp_data(data_file)
    tcp_length = len(tcp_data)
    pseudo_header = create_pseudo_header(source_ip, dest_ip, tcp_length)

    original_checksum = int.from_bytes(tcp_data[16:18], "big")
    tcp_zero_checksum = tcp_data[:16] + b"\x00\x00" + tcp_data[18:]

    checksum_data = pseudo_header + tcp_zero_checksum
    computed_checksum = calculate_checksum(checksum_data)

    return "PASS" if computed_checksum == original_checksum else "FAIL"


def main():
    results = []
    for i in range(10):
        addr_file = f"./packets/tcp_addrs_{i}.txt"
        data_file = f"./packets/tcp_data_{i}.dat"
        result = validate_tcp_checksum(addr_file, data_file)
        results.append(result)
        print(result)


if __name__ == "__main__":
    main()
