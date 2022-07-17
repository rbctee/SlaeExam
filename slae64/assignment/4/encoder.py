import argparse
import random

# Reference:
# https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
def chunks(lst, n):

    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def encode_chunk(chunk: bytes) -> bytes:

    assert len(chunk) == 7

    encoded_chunk = bytearray()
    available_bytes = list(set(range(1,255)) - set(chunk))
    xor_byte = random.choice(available_bytes)

    assert xor_byte not in chunk

    encoded_chunk.append(xor_byte)

    for index, chunk_byte in enumerate(chunk):
        encoded_chunk.append(chunk_byte ^ xor_byte)

    assert len(encoded_chunk) == 8
    assert 0 not in encoded_chunk

    return encoded_chunk

def encode_shellcode(shellcode: bytes) -> bytes:

    encoded_shellcode = bytearray()

    xor_byte = random.choice(range(1, 256))
    encoded_shellcode.append(xor_byte)

    print(f"[+] Xoring bytes with the byte {hex(xor_byte)}")

    for b in shellcode:
        encoded_shellcode.append(b ^ xor_byte)

    print(f"[+] Size of intermediate encoded shellcode is {len(encoded_shellcode)}")
    if (len(encoded_shellcode) % 7) != 0:
        print(f"[+] Adding padding to shellcode")

        num_pad_bytes = 7 - (len(encoded_shellcode) % 7)

        for x in range(num_pad_bytes):
            encoded_shellcode.append(0)
    else:
        print(f"[+] No need to add padding to the shellcode")

    print(f"[+] Slicing the shellcode into chunks of 7 bytes")
    bytes_chunks = list(chunks(encoded_shellcode, 7))
    encoded_shellcode = bytearray()

    for c in bytes_chunks:
        
        encoded_chunk = encode_chunk(c)
        encoded_shellcode.extend(encoded_chunk)

    print(f"[+] Finished encoding chunks")

    return encoded_shellcode

def read_shellcode(input_file) -> bytes:

    with open(input_file, 'rb') as f:
        return f.read()

def manage_shellcode_encoding(input_file, output_file=None):

    print(f"\n[#] ENCODING")

    shellcode = read_shellcode(input_file)
    encoded_shellcode = encode_shellcode(shellcode)

    print(f"[+] Encoded shellcode (HEX): {encoded_shellcode.hex()}")

    s = ""
    for x in encoded_shellcode:
        s += f"{hex(x)},"

    print("[+] Assembly data: " + s[:-1])

    if output_file:
        with open(output_file, 'wb') as f:
            f.write(encoded_shellcode)

    return encoded_shellcode

def decode_chunk(encoded_chunk: bytes) -> bytes:

    assert len(encoded_chunk) == 8

    xor_byte = encoded_chunk[0]
    decoded_chunk = bytearray()

    for eb in encoded_chunk[1:]:
        decoded_chunk.append(eb ^ xor_byte)

    assert len(decoded_chunk) == 7
    return decoded_chunk


def decode_shellcode(encoded_shellcode: bytes) -> bytes:

    decoded_shellcode = bytearray()

    assert len(encoded_shellcode) % 8 == 0
    encoded_chunks = list(chunks(encoded_shellcode, 8))

    print(f"[+] Decoding chunks")
    for ec in encoded_chunks:

        decoded_chunk = decode_chunk(ec)
        decoded_shellcode.extend(decoded_chunk)

    xor_byte = decoded_shellcode[0]

    if decoded_shellcode[-1] == 0:
        print(f"Removing padding bytes")
        num = 0

        for x in decoded_shellcode[::-1]:
            if x == 0:
                num += 1
            else:
                break

        decoded_shellcode = decoded_shellcode[:-num]

    xor_byte = decoded_shellcode[0]
    print(f"[+] Xoring bytes with the byte {hex(xor_byte)}")

    for index, b in enumerate(decoded_shellcode[1:]):
        decoded_shellcode[index + 1] = b ^ xor_byte
    decoded_shellcode = decoded_shellcode[1:]

    print(f"[+] Decoded shellcode (HEX): {decoded_shellcode.hex()}")
    print(f"[+] Size of decoded shellcode: {len(decoded_shellcode)} bytes")

    return decoded_shellcode


def manage_shellcode_decoding(encoded_shellcode: bytes) -> bytes:

    print(f"\n[#] DECODING")

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

    assert 0 not in encoded_shellcode

    decoded_shellcode = manage_shellcode_decoding(encoded_shellcode)
    assert decoded_shellcode == shellcode
    print(f"[+] Decoded shellcode is equal to the original shellcode")

if __name__ == '__main__':

    main()
