import argparse
import random

# Rotate left: 0b1001 --> 0b0011
def bitwise_rol(byte: int, rotation: int, max_bits: int) -> int:
    rotation = rotation % max_bits
    max_value = 2 ** max_bits - 1

    rotated_byte = ((byte << rotation) & max_value) | ((byte & max_value) >> (max_bits - rotation))

    return rotated_byte 
 
# Rotate right: 0b1001 --> 0b1100
def bitwise_ror(byte: int, rotation: int, max_bits: int) -> int:
    rotation = rotation % max_bits
    max_value = 2 ** max_bits - 1

    rotated_byte = ((byte & max_value) >> rotation) | (byte << (max_bits - rotation) & max_value)
    return rotated_byte

def bitwise_not(byte: int) -> int:
    return 255 - byte

def gen_random_rotations(ms_byte: int, ls_byte: int) -> tuple:
    ROT_EVEN = random.randrange(1, 256)
    ROT_ODD = random.randrange(1, 256)

    while ROT_EVEN == ls_byte:
        print(f"[+] ROT EVEN ({ROT_EVEN}) is equal to the Least Significant Byte of the shellcode length ({ls_byte})")
        ROT_EVEN = random.randrange(1, 8)

    while ROT_ODD == ms_byte:
        print(f"[+] ROT EVEN ({ROT_ODD}) is equal to the Most Significant Byte of the shellcode length ({ms_byte})")
        ROT_ODD = random.randrange(1, 8)

    return ROT_EVEN, ROT_ODD

def encode_shellcode(shellcode: bytes) -> bytes:
    encoded_shellcode = bytearray()
    print(f"[+] Original non-encoded shellcode (HEX): {shellcode.hex()}")

    shellcode_length_least_byte = len(shellcode) % 256
    shellcode_length_most_byte = len(shellcode) // 256

    ROT_EVEN, ROT_ODD = gen_random_rotations(ms_byte=shellcode_length_most_byte, ls_byte=shellcode_length_least_byte)
    shellcode_length_least_byte = shellcode_length_least_byte ^ ROT_EVEN
    shellcode_length_most_byte = shellcode_length_most_byte ^ ROT_ODD

    print(f"[+] Rotations for even-index bytes: {ROT_EVEN} (hex: {hex(ROT_EVEN)})")
    print(f"[+] Rotations for odd-index bytes: {ROT_ODD} (hex: {hex(ROT_ODD)})")
    print(f"[+] Least Significant Byte of Shellcode Length XOR-ed with ROT_EVEN: {shellcode_length_least_byte} (hex: {hex(shellcode_length_least_byte)})")
    print(f"[+] Most Significant Byte of Shellcode Length XOR-ed with ROT_ODD: {shellcode_length_most_byte} (hex: {hex(shellcode_length_most_byte)})")

    encoded_shellcode.append(ROT_EVEN)
    encoded_shellcode.append(ROT_ODD)
    encoded_shellcode.append(shellcode_length_least_byte)
    encoded_shellcode.append(shellcode_length_most_byte)

    print(f"[+] Helper bytes for decoding (HEX): {encoded_shellcode.hex()}")

    # 1. Rotate bytes
    #   1.1. EVEN index -> Rotate to the Right ROT_EVEN times
    #   1.2. ODD index -> Rotate to the Left ROT_ODD times
    # 2. NOT each byte
    # 3. XOR each byte with the Least Significant Byte of the shellcode length
    #   (shellcode_length_least_byte), which is XOR-ed with ROT_EVEN to avoid null_bytes
    print(f"\n[#] Encoding ...")

    for index, byte in enumerate(shellcode):
        if index % 2 == 0:
            # even index byte
            # print(f"[+] EVEN | Original byte: {hex(byte)}")

            encoded_byte = bitwise_ror(byte, ROT_EVEN, 8)
            # print(f"[+] EVEN | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] EVEN | NOT-ed byte: {hex(encoded_byte)}")

            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] EVEN | Xored byte: {hex(encoded_byte)}\n")
        else:
            # odd index byte
            # print(f"[+] ODD | Original byte: {hex(byte)}")

            encoded_byte = bitwise_rol(byte, ROT_ODD, 8)
            # print(f"[+] ODD | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] ODD | NOT-ed byte: {hex(encoded_byte)}")

            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] ODD | Xored byte: {hex(encoded_byte)}\n")
        
        encoded_shellcode.append(encoded_byte)

    assert 0x00 not in encoded_shellcode
    return encoded_shellcode

def read_shellcode(input_file) -> bytes:
    with open(input_file, 'rb') as f:
        return f.read()

def manage_shellcode_encoding(input_file, output_file=None):
    shellcode = read_shellcode(input_file)

    encoded_shellcode = encode_shellcode(shellcode)

    print(f"[+] Encoded shellcode (HEX): {encoded_shellcode.hex()}")
    if output_file:
        with open(output_file, 'wb') as f:
            f.write(encoded_shellcode)

    return encoded_shellcode

def decode_shellcode(encoded_shellcode: bytes) -> bytes:
    decoded_shellcode = bytearray()

    ROT_EVEN, ROT_ODD = encoded_shellcode[:2]
    shellcode_length_least_byte = encoded_shellcode[2]
    shellcode_length_most_byte = encoded_shellcode[3]
    encoded_shellcode_main = encoded_shellcode[4:]

    print(f"\n[#] Decoding ...")
    for index, encoded_byte in enumerate(encoded_shellcode_main):
        if index % 2 == 0:
            # print(f"[+] EVEN | XOR-ed byte: {hex(encoded_byte)}")

            decoded_byte = encoded_byte ^ shellcode_length_least_byte
            # print(f"[+] EVEN | Rotated byte: {hex(decoded_byte)}")

            decoded_byte = bitwise_not(decoded_byte)
            # print(f"[+] EVEN | Rotated byte: {hex(decoded_byte)}")

            decoded_byte = bitwise_rol(decoded_byte, ROT_EVEN, 8)
            # print(f"[+] EVEN | Original byte: {hex(decoded_byte)}\n")
        else:
            # print(f"[+] ODD | XOR-ed byte: {hex(encoded_byte)}")

            decoded_byte = encoded_byte ^ shellcode_length_least_byte
            # print(f"[+] ODD | NOT-ed byte: {hex(decoded_byte)}")

            decoded_byte = bitwise_not(decoded_byte)
            # print(f"[+] ODD | Rotated byte: {hex(decoded_byte)}")

            decoded_byte = bitwise_ror(decoded_byte, ROT_ODD, 8)
            # print(f"[+] ODD | Original byte: {hex(decoded_byte)}\n")

        decoded_shellcode.append(decoded_byte)

    print(f"[+] Decoded shellcode (HEX): {decoded_shellcode.hex()}")
    return decoded_shellcode


def manage_shellcode_decoding(encoded_shellcode: bytes) -> bytes:
    decoded_shellcode = decode_shellcode(encoded_shellcode)
    return decoded_shellcode

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="File containing shellcode to encode", required=True)
    parser.add_argument("-o", "--output", help="Store the encoded shellcode in this file", required=False)

    args = parser.parse_args()
    input_file = args.input
    output_file = args.output

    shellcode = read_shellcode(input_file)
    encoded_shellcode = manage_shellcode_encoding(input_file, output_file)

    assert shellcode == manage_shellcode_decoding(encoded_shellcode)

if __name__ == '__main__':
    main()
