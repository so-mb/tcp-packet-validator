def create_tcp_data_file():
    data = bytes([0x00] * 16)  # Create short data of 16 bytes of zeros as an example
    filename = 'packets/tcp_data_xx.dat'
    
    with open(filename, 'wb') as file:
        file.write(data)
    
    print(f"Created {filename} with data length: {len(data)} bytes.")

if __name__ == "__main__":
    create_tcp_data_file()
