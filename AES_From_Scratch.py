import numpy as np
from BitVector import BitVector
from time import time


def xor_hex_string_with_int(a: str, b: int):
    return hex(int(a, 16) ^ b)


def xor_hex_string_with_xor_hex_string(a: str, b: str):
    return hex(int(a, 16) ^ int(b, 16))

#S-Box Substitution Operation
def s_box_substitution(hex_str: str) -> str:
    int_value = int(hex_str, 16)
    if int_value == 0:
        return '0x63'
    val = BitVector(intVal=int_value, size=8).gf_MI(BitVector(bitstring='100011011'), 8).int_val()
    val = bin(val)[2:]
    val = '0' * (8 - len(val)) + val
    val = np.array([int(val[7 - i]) for i in range(len(val))]).reshape((8, 1))
    affine_trans_mat_r1 = np.array([1, 0, 0, 0, 1, 1, 1, 1])
    affine_trans_mat = np.zeros((8, 8), dtype=np.int32)
    for i in range(8):
        affine_trans_mat[i] += np.roll(affine_trans_mat_r1, i)
    val = affine_trans_mat @ val
    val = val.reshape(8)
    affine_vec = np.array([1, 1, 0, 0, 0, 1, 1, 0])
    for i in range(8):
        val[i] = (affine_vec[i] + val[i]) % 2
    transformed_val = 0
    for i in range(8):
        transformed_val += val[i] << i
    return hex(transformed_val)

# Inverse S-Box Substitution for Decryption
def inv_s_box_substitution(hex_str: str) -> str:
    int_value = int(hex_str, 16)
    if hex_str == '0x63':
        return '0x00'
    val = bin(int_value)[2:]
    val = '0' * (8 - len(val)) + val
    val = np.array([int(val[7 - i]) for i in range(len(val))]).reshape((8, 1))
    inv_affine_trans_mat_r1 = np.array([0, 0, 1, 0, 0, 1, 0, 1])
    inv_affine_trans_mat = np.zeros((8, 8), dtype=np.int32)
    for i in range(8):
        inv_affine_trans_mat[i] += np.roll(inv_affine_trans_mat_r1, i)
    val = inv_affine_trans_mat @ val
    val = val.reshape(8)
    inv_affine_vec = np.array([1, 0, 1, 0, 0, 0, 0, 0])
    for i in range(8):
        val[i] = (inv_affine_vec[i] + val[i]) % 2
    transformed_val = 0
    for i in range(8):
        transformed_val += val[i] << i
    transformed_val = BitVector(intVal=transformed_val, size=8).gf_MI(BitVector(bitstring='100011011'), 8).int_val()
    return hex(transformed_val)

#Mix Columns Operation
def matrix4x4_gf_multiplication(mat_a_bs, mat_b_hex):
    output = mat_b_hex.copy()
    for i in range(4):
        for j in range(4):
            row = mat_a_bs[i]
            col = mat_b_hex[:, j]
            temp_val = 0
            for idx in range(4):
                temp_val ^= row[idx].gf_multiply_modular(BitVector(hexstring=col[idx][2:]),
                                                         BitVector(bitstring='100011011'), 8).int_val()
            output[i][j] = hex(temp_val)
    return output


class AES:
    # Define MixColumns matrices
    MIXER = [
        [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
        [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
        [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
    ]

    INV_MIXER = [
        [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
        [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
        [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
        [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
    ]

    # Round Constants for key Expansion
    ROUND_CONST = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def __init__(self, key: str, verbose: bool = True) -> None:
        super().__init__()
        self.key_plaintext = key[:16] if len(key) > 16 else key + '0' * (16 - len(key))
        self.verbose = verbose
        tic = time()
        
        #key Expansion
        self.round_key = []
        self.round_key.append(np.array([
            hex(ord(char)) for char in self.key_plaintext
        ]).reshape((4, 4), order='F'))

        # Generate Round keys
        for round_no in range(10):
            self.round_key.append(self.generate_round_key(round_no))
        toc = time()
        if self.verbose:
            print('Round Key Generation Time: ', toc - tic)

    # Generate Round key for key Expansion
    def generate_round_key(self, round_no: int):
        temp_round_key = self.round_key[round_no].copy()
        temp_round_sub_key = temp_round_key[:, -1].copy()

        #Rotate lat column (Rotation in key expanion)
        # rotation
        temp_round_sub_key = np.roll(temp_round_sub_key, -1)

        #Apply S-Box substitution to rotated column (SubBytes in key Expansion)
        # substitution
        for i in range(len(temp_round_sub_key)):
            temp_round_sub_key[i] = s_box_substitution(temp_round_sub_key[i])

        # Add Round Constant (Key Expansion)    
        # add round constant
        temp_round_sub_key[0] = xor_hex_string_with_int(temp_round_sub_key[0], AES.ROUND_CONST[round_no])

        # XOR columns for round key generation (key Expansion)

        for i in range(4):
            temp_round_key[i, 0] = xor_hex_string_with_xor_hex_string(temp_round_key[i, 0], temp_round_sub_key[i])
        for col_no in range(1, 4):
            for row_no in range(4):
                temp_round_key[row_no, col_no] = xor_hex_string_with_xor_hex_string(temp_round_key[row_no, col_no - 1],
                                                                                    temp_round_key[row_no, col_no])
        return temp_round_key

    # Add Round key operation
    def add_round_key(self, round_key_no: int, state_matrix):
        for i in range(4):
            for j in range(4):
                state_matrix[i][j] = xor_hex_string_with_xor_hex_string(
                    state_matrix[i][j], self.round_key[round_key_no][i][j]
                )

    # Encryption function
    def encrypt(self, plain_text: str, inp_type: str = 'str') -> str:
        tic = time()
        if inp_type == 'str':
            updated_plain_text = plain_text[:16] if len(plain_text) > 16 else plain_text + ' ' * (16 - len(plain_text))
            state_matrix = np.array([
                hex(ord(char)) for char in updated_plain_text
            ]).reshape((4, 4), order='F')
        else:
            state_matrix = np.array([
                hex(int(char, 16)) for char in plain_text.split(' ')
            ]).reshape((4, 4), order='F')

        #Initial Add Round key
        # Round 0
        self.add_round_key(0, state_matrix)

        # Main AES Rounds
        # Round 1-10
        for round_no in range(1, 11):

            # SubBytes operation
            # Substitution
            for i in range(4):
                for j in range(4):
                    state_matrix[i][j] = s_box_substitution(state_matrix[i][j])

            # Shift Rows operation
            # Shift Row
            for i in range(1, 4):
                state_matrix[i, :] = np.roll(state_matrix[i, :], -i)
            # Mix Column (For round 1-9)
            if round_no != 10:
                state_matrix = matrix4x4_gf_multiplication(AES.MIXER, state_matrix)
            # Add Round Key
            self.add_round_key(round_no, state_matrix)

        cipher_text = ""
        for col in range(4):
            for row in range(4):
                cipher_text += (state_matrix[row][col][2:] + ' ')
        toc = time()
        if self.verbose:
            print('Encryption Time: ', toc - tic)
        return cipher_text.strip()

    # Decryption function
    def decrypt(self, cipher_text: str, inp_type: str = 'str') -> str:
        tic = time()
        cipher_text_arr = [hex(int(chr_grp, 16)) for chr_grp in cipher_text.split(' ')]
        if len(cipher_text_arr) != 16:
            raise Exception('Invalid Cipher Text! Expected Cipher Text Format is Space-separated Hex Values!')
        cipher_state_matrix = np.array(cipher_text_arr).reshape((4, 4), order='F')
        # Round 0-9
        for round_no in range(0, 10):
            # Add Round Key
            self.add_round_key(10 - round_no, cipher_state_matrix)
            # Mix Column (For round 1-9)
            if round_no != 0:
                cipher_state_matrix = matrix4x4_gf_multiplication(AES.INV_MIXER, cipher_state_matrix)
            # Shift Row
            for i in range(1, 4):
                cipher_state_matrix[i, :] = np.roll(cipher_state_matrix[i, :], i)
            # Substitution
            for i in range(4):
                for j in range(4):
                    cipher_state_matrix[i][j] = inv_s_box_substitution(cipher_state_matrix[i][j])
        # Round 10
        self.add_round_key(0, cipher_state_matrix)

        plain_text = ""
        for col in range(4):
            for row in range(4):
                if inp_type == 'str':
                    plain_text += chr(int(cipher_state_matrix[row][col], 16))
                else:
                    plain_text += cipher_state_matrix[row][col][2:]
        toc = time()
        if self.verbose:
            print('Decryption Time: ', toc - tic)
        return plain_text

'''
# we store the english words in a list (maybe a dictionary would be better)
ENGLISH_WORDS = []
# load the english words
def get_data():

    dictionary = open('decryptedtext.txt', 'r')

    # initialize the ENGLISH_WORDS list with the words present in the file
    # every word is in a distinct line so that why we have to split('\n')
    for word in dictionary.read().split('\n'):
        print(word)
        ENGLISH_WORDS.append(word)

    dictionary.close()
'''

if __name__ == '__main__':
    print('----- Demonstration -----')
    # Initialize AES with a sample key
    k = 'Thats my Kung Fu my kan wangu am'
    print('Key:', k)
    aes = AES(k)

    #Sample plaintext
    pt = "Two One Nine Two"
    print('Plain Text:', pt)

    # Encrypt the plaintext
    ct = aes.encrypt(pt, 'str')
    print('Encrypted Text:', ct)

    # Decrypt the ciphertext
    dpt = aes.decrypt(ct)
    print('Decrypted Text:', dpt)
    print()
    print('---- Interactive Mode ---')
    while True:
        k = input('Enter key (\'q\' to exit): ')
        if k.lower() == 'q':
            break
        aes = AES(k)
        pt = input('Enter Plain Text: ')
        ct = aes.encrypt(pt, 'str')
        print('Encrypted Text:', ct)
        dpt = aes.decrypt(ct)
        print('Decrypted Text:', dpt)