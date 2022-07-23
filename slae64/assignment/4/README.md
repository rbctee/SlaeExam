# Assignment 4

Encoding scheme:

- xor each byte with a specific byte
- take a group of 7 bytes
- find a byte that XORed to the other 7 bytes doesn't generate NULL bytes in shellcode
