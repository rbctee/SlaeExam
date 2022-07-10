package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "math/bits"
)

const NUM_ROUNDS uint = 128
const PADDING_BLOCK_SIZE uint = 8

func remove_pkcs7_padding(src []byte, blockSize uint) []byte {

    var last_byte byte = src[len(src) - 1]

    if last_byte >= 0x1 && last_byte <= 0x7 {

        for i := len(src) - 1; i > (len(src) - int(last_byte)); i-- {
            if src[i] != last_byte {
                fmt.Printf("[!] Incorrect padding. Check manually\n")
                return src[:]
            }
        }

        return src[:len(src) - int(last_byte)]

    } else {

        for i := len(src) - 8; i < len(src); i++ {
            if (src[i] != last_byte) {
                fmt.Printf("[!] Incorrect padding. Check manually\n")
                return src[:]
            }
        }

        return src[:len(src) - 8]
    }
}

func calculate_sbox() [256]byte {

    var p byte = 1
    var q byte = 1
    var sbox [256]byte
    
    /* loop invariant: p * q == 1 in the Galois field */
    for {

        /* multiply p by 3 */
        if p & 0x80 >= 128 {
            p = p ^ (p << 1) ^ 0x1B
        } else {
            p = p ^ (p << 1) ^ 0
        }

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4

        if q & 0x80 >= 128 {
            q = q ^ 0x09
        }

        /* compute the affine transformation */
        var xformed byte = q ^ bits.RotateLeft8(q, 1) ^ bits.RotateLeft8(q, 2) ^ bits.RotateLeft8(q, 3) ^ bits.RotateLeft8(q, 4)

        sbox[p] = xformed ^ 0x63

        if p == 1 {
            break
        }
    }

    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63

    return sbox
}

func treyfer_decrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var top uint8 = 0;
    var bottom uint8 = 0;

    for j := uint(0); j < NUM_ROUNDS; j++ {
        for i := 7; i >= 0; i-- {

            top = text[i] + key[i];
            top = sbox[top];

            bottom = text[(i + 1) % 8];
            bottom = (bottom >> 1) | (bottom << 7);

            text[(i + 1) % 8] = bottom - top;
        }
    }

    return text
       
}

func main() {

    var input_file = flag.String("input", "encrypted.bin", "File containing the encrypted shellcode")
    var output_file = flag.String("output", "decrypted.bin", "Path of the output file")
    flag.Parse()

    if flag.NFlag() == 0 {
        flag.Usage()
        return
    }

    fmt.Printf("[+] Reading the encrypted shellcode from the input file\n")
    data, err := ioutil.ReadFile(*input_file)
    if err != nil {
        fmt.Printf("[!] Error reading the input file\n")
        return
    }

    var key = [8]byte{65, 65, 65, 65, 65, 65, 65, 65}

    fmt.Printf("[+] Calculating the S-Box\n")
    var sbox [256]byte = calculate_sbox()

    
    var decrypted_shellcode []byte = make([]byte, len(data))

    var chunk [8]byte

    fmt.Printf("[+] Decrypting the shellcode\n")
    for i := 0; i < len(data); i++ {
        chunk[i % 8] = data[i]
        
        if i % 8 == 7 {
            chunk = treyfer_decrypt(chunk, key, sbox)

            for j := i - 7; j <= i; j++ {
                decrypted_shellcode[j] = chunk[j % 8]
            }
        }
    }

    fmt.Printf("[+] Removing padding from the decrypted shellcode\n")
    decrypted_shellcode = remove_pkcs7_padding(decrypted_shellcode, PADDING_BLOCK_SIZE)

    fmt.Printf("[+] Saving the encrypted shellcode into the output file\n")
    err = ioutil.WriteFile(*output_file, decrypted_shellcode, 0644)
    if err != nil {
        fmt.Printf("[!] Error writing the encrypted shellcode to the output file\n")
        return
    }
}
