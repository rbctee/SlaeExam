import argparse
import random

XOR_BYTE = 0

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

    global XOR_BYTE

    encoded_shellcode = bytearray()

    XOR_BYTE = random.choice(range(1, 256))

    print(f"[+] Xoring bytes with the byte {hex(XOR_BYTE)}")

    for b in shellcode:
        encoded_shellcode.append(b ^ XOR_BYTE)

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

    if decoded_shellcode[-1] == 0:
        print(f"[+] Removing padding bytes")
        num = 0

        for x in decoded_shellcode[::-1]:
            if x == 0:
                num += 1
            else:
                break

        decoded_shellcode = decoded_shellcode[:-num]

    print(decoded_shellcode.hex())

    print(f"[+] Xoring bytes with the byte {hex(XOR_BYTE)}")

    for index, b in enumerate(decoded_shellcode):
        decoded_shellcode[index] = b ^ XOR_BYTE

    decoded_shellcode = decoded_shellcode

    print(f"[+] Decoded shellcode (HEX): {decoded_shellcode.hex()}")
    print(f"[+] Size of decoded shellcode: {len(decoded_shellcode)} bytes")

    return decoded_shellcode


def manage_shellcode_decoding(encoded_shellcode: bytes) -> bytes:

    print(f"\n[#] DECODING")

    decoded_shellcode = decode_shellcode(encoded_shellcode)
    return decoded_shellcode

def generate_decoder_nasm(shellcode: bytes, input_template_file: str = "decoder_template.txt", output_nasm_file: str = "decoder.nasm"):

    shellcode_length = len(shellcode)
    assert shellcode_length <= 65535, "[!] Shellcode too big"

    try:
        with open(input_template_file) as f:
            template = f.read()
    except Exception as e:
        print(e)
        print(f"[!] Error while reading the decoder template")
        return

    shellcode_length_instruction = f"add cl, {shellcode_length}"

    if shellcode_length > 256:
        shellcode_length_instruction = f"mov cx, {shellcode_length}"

    encoded_shellcode = ",".join([hex(eb) for eb in shellcode])

    template = template.replace("{{ SHELLCODE_LENGTH_INSTRUCTION }}", shellcode_length_instruction)
    template = template.replace("{{ XOR_BYTE }}", hex(XOR_BYTE))
    template = template.replace("{{ ENCODED_SHELLCODE }}", encoded_shellcode)

    try:
        with open(output_nasm_file, "w") as f:
            f.write(template)
    except Exception as e:
        print(e)
        print(f"[!] Error while creating the decoder NASM file")
        return


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

    print(f"[+] Generating the decoder program")
    generate_decoder_nasm(encoded_shellcode)

if __name__ == '__main__':

    main()
