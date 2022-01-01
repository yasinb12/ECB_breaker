import base64, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import Counter


# Consistent but unknown key
list = [21, 200, 56, 242, 28, 153, 199, 148, 241, 165, 143, 49, 73, 54, 251, 42]
unknown_key = bytes(list)
my_string = "Lorem ipsum dolor amir eret colomun"


def is_aes_128_ecb(oracle, input_string, encoding='base64'):
    ciphertext = oracle(input_string)
    decoded_msg = b''
    if encoding == 'base64':
        decoded_msg = base64.b64decode(ciphertext)
    elif encoding == 'hex':
        decoded_msg = bytes.fromhex(ciphertext)
    scores = []
    blocks = [decoded_msg[i:i + 16] for i in range(0, len(decoded_msg), 16)]
    # Count the occurrence of each ciphertext block in the ciphertext
    block_duplicates = Counter(blocks).values()
    max_block_duplicate = max(block_duplicates)
    scores.append(max_block_duplicate)
    best_score = max(scores)
    if best_score > 1:
        return True
    else:
        return False


def detect_mode(oracle):
    in1 = bytes([random.randint(1, 127)]) * 48
    if is_aes_128_ecb(oracle, in1) == False:
        return "encrypted with CBC"
    else:
        return "encrypted with ECB"


def ecb_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)


def ecb_encryption_oracle(your_string, encoding='base64'):
    # string we are trying to decrypt ("unknown-string")
    unknown_string = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    plaintext = pad(b''.join((your_string, base64.b64decode(unknown_string))), 16)
    ciphertext = ecb_encrypt(unknown_key, plaintext)
    if encoding == 'base64':
        return base64.b64encode(ciphertext)
    elif encoding == 'hex':
        return ciphertext.hex()


def find_block_size(oracle, in_string):
    size1 = 0
    oracle_outputs = [base64.b64decode(oracle(in_string[:i])) for i in range(1, 33)]
    for size in range(1, 33):
        first_bytes = oracle_outputs[size - 1][:size]
        for i in range(size, len(oracle_outputs)):
            ith_bytes = oracle_outputs[i][:size]
            if ith_bytes != first_bytes:
                break
            else:
                size1 = size
    return size1


def brute_byte(oracle, test_input, recovered_bytes, target_output):
    char_dict = {}
    count2 = 0
    result = b''
    # creates a "codebook" that maps each ASCII character (0-255) to an output of the ECB oracle
    for i in range(255):
        test1 = test_input + recovered_bytes + bytes([i])
        outtest1 = base64.b64decode(oracle(test1))[:16]
        char_dict[bytes([i])] = outtest1
        count2 += 1
    # determines the codebook entry that matches the current output of the oracle -> saves the matching character
    for char, oracle_answer in char_dict.items():
        if oracle_answer == target_output:
            result = char
            break
    return result


def decrypt_string(oracle, block_size):
    start = 1
    block_bound1, block_bound2 = 0, block_size
    in1 = b'A' * block_size
    recov_bytes = b''
    # Recovers the first 16 bytes of the message
    for a in range(block_size):
        in2 = b''.join((in1, recov_bytes))[start:]
        output = base64.b64decode(oracle(in2))[block_bound1:block_bound2]
        recov_bytes += brute_byte(oracle, in2, recov_bytes, output)
        start += 2
    block_bound1 += block_size
    block_bound2 += block_size
    start1, start2 = 1, 1
    count2 = 0
    bytes_left = True
    # Recovers the remainder of the message
    while bytes_left:
        in3 = in1[start1:]
        s_out = base64.b64decode(oracle(in3))[block_bound1:block_bound2]
        new_byte = brute_byte(oracle, recov_bytes[start2:], b'', s_out)
        if new_byte == b'':
            bytes_left = False
        else:
            recov_bytes += brute_byte(oracle, recov_bytes[start2:], b'', s_out)
        start2 += 1
        start1 += 1
        # whenever a new block of the message is recovered, the section of the output on which the attacker
        # focuses is shifted by the block size (16) -> decryption can continue to the end of the message
        if len(recov_bytes) % block_size == 0:
            block_bound1 += block_size
            block_bound2 += block_size
            start1 = 1
        count2 += 1
    return recov_bytes.decode()


def main():
    size = find_block_size(ecb_encryption_oracle, my_string.encode())
    print(detect_mode(ecb_encryption_oracle), end='\n\n')
    k = decrypt_string(ecb_encryption_oracle, size)
    print('Secret message:\n\n' + k)


if __name__ == '__main__':
    main()
