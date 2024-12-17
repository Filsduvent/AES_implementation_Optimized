
# Simplified menu focused on AES encryption and decryption options

import cripto1Save
import helper

str1 = "1. Encrypt: file name and 16-byte key\n"
str2 = "2. Decrypt: file name and 16-byte key\n"
str3 = "3. Encrypt using Vigenère-based AES\n"
str4 = "4. Decrypt using Vigenère-based AES\n"
str5 = "5. Encrypt with AES 24 byte"
str6 = "6. Decrypt with AES 24 byte"
str7 = "7. Encrypt with AES 32 byte"
str8 = "8. Decrypt with AES 32 byte"


str9 = "9. Exit\n"

while True:
    try:
        choice = int(input(str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8 + str9))
    except ValueError:
        print("Not a number")

    if choice == 1:
        print("Generating AES key")
        key = cripto1Save.randkeygen(16 * 8)
        print("key:", key)
        
        filename = "test"
        msg = helper.readFile(filename + ".txt")
        IV = cripto1Save.IVGen(16 * 8)
        cipher=cripto1Save.encrypt(msg, key, 16*8, "CBC", IV)
        # If encrypt returns a tuple, unpack it
        if isinstance(cipher, tuple):
            elapsed_time, cipher = cipher  # Extract only the cipher
        helper.saveCipher(filename + "_AES128.txt", cipher)
        print("Cipher saved at file:", filename + ".txt")


    elif choice == 2:
        filename = "test"
        strcipher = helper.readFile(filename + "_AES128.txt")
        
        # Split and convert to integers
        try:
            tmp_cipher = strcipher.split(",")
            cipher = [int(i) for i in tmp_cipher]
        except ValueError as e:
            print(f"Error in ciphertext format: {e}")
            continue
        
        plain = cripto1Save.decrypt(cipher, key, 16 * 8, "CBC", IV)
        helper.saveFile(filename + "_AES128_plain.txt", plain)
        print("Decrypted file saved as:", filename + "_AES128_plain.txt")

        
    elif choice == 3:
        print("Generating AES key")
        key = cripto1Save.randkeygen(16 * 8)
        print("key:", key)
        
        filename = "test"
        msg = helper.readFile(filename + ".txt")
        IV = cripto1Save.IVGen(16 * 8)
        cipher=cripto1Save.encrypt(msg, key, 16*8, "VIGENERE", IV)
        # If encrypt returns a tuple, unpack it
        if isinstance(cipher, tuple):
            elapsed_time, cipher = cipher  # Extract only the cipher
        helper.saveCipher(filename + "_AES128_Vigenere.txt", cipher)
        print("Cipher saved at file:", filename + ".txt")

    elif choice == 4:
        filename = "test"
        strcipher = helper.readFile(filename + "_AES128_Vigenere.txt")
        
        # Split and convert to integers
        try:
            tmp_cipher = strcipher.split(",")
            cipher = [int(i) for i in tmp_cipher]
        except ValueError as e:
            print(f"Error in ciphertext format: {e}")
            continue

        plain=cripto1Save.decrypt(cipher, key, 16*8, "VIGENERE", IV)
        helper.saveFile(filename + "_AES128_Vigenere_plain.txt", plain)
        print("Decrypted file saved as:", filename + "_AES128_Vigenere_plain.txt")

    elif choice == 9:
        print("Exited.")
        break
    else:
        print("Please enter a valid entry")
