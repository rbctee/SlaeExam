package main

import (
    "bytes"
    "flag"
    "fmt"
    "io/ioutil"
    "math/bits"
)

const NUM_ROUNDS uint = 128
const PADDING_BLOCK_SIZE int = 8

/*
References:
- https://stackoverflow.com/questions/41579325/golang-how-do-i-decrypt-with-des-cbc-and-pkcs7
*/
func add_pkcs7_padding(src []byte, blockSize int) []byte {

    var text_length int = len(src)

    if text_length % blockSize == 0 {

        var padtext = bytes.Repeat([]byte{byte(0x15)}, blockSize)
        return append(src, padtext...)

    } else {

        var padding = blockSize - text_length % blockSize
        var padtext = bytes.Repeat([]byte{byte(padding)}, padding)
        return append(src, padtext...)
    }
}

/*
References:
- https://stackoverflow.com/questions/69066821/rijndael-s-box-in-c
*/
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

/*
References:
- https://en.wikipedia.org/wiki/Treyfer
*/
func treyfer_encrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var t byte = text[0]

    for i := uint(0); i < (8 * NUM_ROUNDS); i++ {

        t += key[i % 8]
        t = sbox[t] + text[(i + 1) % 8]
        t = bits.RotateLeft8(t, 1)
        text[(i+1) % 8] = t
    }

    return text
}

func main() {

    var input_file = flag.String("input", "shellcode.bin", "Shellcode file containing the raw bytes to encrypt")
    var output_file = flag.String("output", "encrypted.bin", "Path of the output file")
    flag.Parse()

    if flag.NFlag() == 0 {
        flag.Usage()
        return
    }

    fmt.Printf("[+] Reading the shellcode from the input file\n")
    data, err := ioutil.ReadFile(*input_file)
    if err != nil {
        fmt.Printf("[!] Error reading the shellcode from the input file\n")
        return
    }

    var key = [8]byte{65, 65, 65, 65, 65, 65, 65, 65}

    fmt.Printf("[+] Calculating the S-Box\n")
    var sbox [256]byte = calculate_sbox()

    fmt.Printf("[+] Adding padding to the shellcode\n")
    var padded_message = add_pkcs7_padding(data[:], PADDING_BLOCK_SIZE)
    var encrypted_message []byte = make([]byte, len(padded_message))

    var chunk [8]byte

    fmt.Printf("[+] Encrypting the shellcode\n")
    for i := 0; i < len(padded_message); i++ {
        chunk[i % 8] = padded_message[i]
        
        if i % 8 == 7 {
            chunk = treyfer_encrypt(chunk, key, sbox)

            for j := i - 7; j <= i; j++ {
                encrypted_message[j] = chunk[j % 8]
            }
        }
    }

    fmt.Printf("[+] Saving the encrypted shellcode into the output file\n")
    err = ioutil.WriteFile(*output_file, encrypted_message, 0644)
    if err != nil {
        fmt.Printf("[!] Error writing the encrypted shellcode to the output file\n")
        return
    }
}
