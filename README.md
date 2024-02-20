# AES-128-bits Block-Cipher
Implemented AES 128 bits Block Cipher in Python from scratch. In which key is hardcoded in hex string 32 characters. Support all type of strings.

## Object of AES Class
Initially make an object instance of AES Class, to start with AES.

    Object = AES() 

## Encryption
To encrypt any string first make the object then encode the string you want to encrypt then call the encryption function to encrypt.

    Object.encode("string")
    Object.encryption()

To view the encrypted text or the Cipher Text.

    CipherText = Object.cypher()
    print(CipherText)

## Decryption
To decrypt the cipher text with the AES 128 Bits Block Cipher instance Object call the decryption function

    DecryptedText = Object.decrypt("CipherText")
    print(DecryptedText)

## Implementation of AES-128 Bits Block Cipher
To implement the AES Block Cipher from scratch, I used python language. Proper encapsulation and abstraction is ensured in the code (AES Class). 10 rounds of encryption is done in the code.
Following Functions are declared for the encryption and decryption in the code:

*Substitute Box*

*Rotate Rows*

*Mix Columns*

*Add Round Key*

*Key Expansion*

### Substitute Box
AES S-box and Inv S-box is defined in the AES class code for substitute bytes function. This function substitute the the bytes of the start of round relative to the AES S-box and AES Inv S-box in encryption and decryption respectively.

### Rotate Rows
This function rotates the rows by the fixed number [0,1,2,3] in left and right direction accordingly to encryption and decryption respectively.

### Mix Column
This function uses initially defined Mix Column Matrix and Inv Mix Column Matrix in the AES code for encryption and decryption respectively. This function uses Galois Field, for which galois is imported from Python Library galois(_irreducible_poly = [1,0,0,0,1,1,0,1,1]) 

### Add Round Key
This function XOR the 4 words of the key with the result after the Mix Column.

### Key Expansion
This function processes with the creation of the Object instance. It uses Rotate Rows and Substitute Box function for the expansion of 4 words key to 44 words key. And group of 4 keys are used in each round.
