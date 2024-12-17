import time

# Vigenère Cipher substitution with key as bytes
def vigenere_substitute(data, key):
    key_repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([(byte + k) % 256 for byte, k in zip(data, key_repeated)])

def vigenere_reverse(data, key):
    key_repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([(byte - k) % 256 for byte, k in zip(data, key_repeated)])

# AES-like transformations
def shift_rows(state):
    return [state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]]

def inverse_shift_rows(state):
    return [state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]]

def mix_columns(state):
    for i in range(4):
        a = state[i]
        b = (a << 1) ^ 0x1B if a & 0x80 else a << 1
        state[i] ^= b
    return state

def add_round_key(state, round_key):
    return [s ^ rk for s, rk in zip(state, round_key)]

# AES Round
def aes_round(state, key):
    state = vigenere_substitute(state, key)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, key)
    return state

# Inverse AES Round
def inverse_aes_round(state, key):
    state = add_round_key(state, key)
    state = mix_columns(state)  # Simplified
    state = inverse_shift_rows(state)
    state = vigenere_reverse(state, key)
    return state

# Encryption with PKCS#7 Padding and Debugging
def aes_encrypt_file(input_file, output_file, key):
    round_key = [ord(k) for k in key[:16]]
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            block = f_in.read(16)
            if not block:
                break

            # Apply padding to the last block
            if len(block) < 16:
                padding_length = 16 - len(block)
                block += bytes([padding_length] * padding_length)
                print(f"Encrypting padded block: {block}")  # Debug
            elif len(f_in.peek(1)) == 0:
                block += bytes([16] * 16)
                print(f"Encrypting full padded block: {block}")  # Debug
            
            state = list(block)

            for _ in range(10):
                state = aes_round(state, round_key)
                state = [s % 256 for s in state]
            
            f_out.write(bytes(state))
    return "Encryption completed."

# Decryption with Padding Check and Debugging
def aes_decrypt_file(input_file, output_file, key):
    round_key = [ord(k) for k in key[:16]]
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            block = f_in.read(16)
            if not block:
                break
            
            state = list(block)

            for _ in range(10):
                state = inverse_aes_round(state, round_key)
                state = [s % 256 for s in state]
            
            # Check if it's the last block
            next_block = f_in.peek(1)
            if len(next_block) == 0:
                padding_length = state[-1]
                print(f"Decrypted last block with padding: {state}")  # Debug
                print(f"Padding length found: {padding_length}")  # Debug
                if padding_length < 1 or padding_length > 16:
                    raise ValueError("Invalid padding length")
                
                # Check if all padding bytes match
                if state[-padding_length:] != [padding_length] * padding_length:
                    raise ValueError("Invalid padding")
                
                # Remove padding bytes
                state = state[:-padding_length]
            
            f_out.write(bytes(state))
    return "Decryption completed."

# Example usage
key = "vigenerekey16bit"
input_file = "test.txt"
encrypted_file = "testencrypted_outputs.txt"
decrypted_file = "testdecrypted_outputs.txt"

# Encrypt the file
encryption_times = aes_encrypt_file(input_file, encrypted_file, key)
print("Encryption phase times:", encryption_times)

# Decrypt the file
decryption_times = aes_decrypt_file(encrypted_file, decrypted_file, key)
print("Decryption phase times:", decryption_times)
