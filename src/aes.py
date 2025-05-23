
import os

class AES:
    # s-box for encryption
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # round constants
    rcon = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    ]

    # inverse S-box for decryption
    inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    def __init__(self, key):
        self.expand_key(key)

    def expand_key(self, key):
        # Izveido vietu 44 vārdiem (11 round keys, katra pa 4 vārdiem)
        self.round_keys = [[0] * 4 for _ in range(44)]
        
        # Pirmā round key ir oriģinālā atslēga (pirmie 4 vārdi)
        for i in range(4):
            self.round_keys[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
        
         # Ģenerē pārējās round keys
        for i in range(4, 44):
            # Paņem iepriekšējo vārdu kā pagaidu masīvu
            temp = list(self.round_keys[i-1])

            # Katram ceturtajam vārdam veic operācijas
            if i % 4 == 0:
                  # Rotē vārdu pa kreisi (pirmais elements kļūst par pēdējo)
                temp = temp[1:] + temp[:1]
                 # Katru baitu aizvieto ar S-box vērtību
                temp = [self.sbox[b] for b in temp]
                # Pirmo baitu XORo ar round konstanti
                temp[0] ^= self.rcon[i//4-1]
                
             # Jauno vārdu iegūst XORojot ar vārdu, kas ir 4 pozīcijas atpakaļ
            for j in range(4):
                self.round_keys[i][j] = self.round_keys[i-4][j] ^ temp[j]

    def add_round_key(self, state, round_key):
        for i in range(4): # rindas
            for j in range(4): # kolonnas
                state[i][j] ^= round_key[i][j] # XOR starp state[i][j] un raunda atslēgas vērtību
        return state # Atgriež jauno state

    def sub_bytes(self, state):
       #State ir 4x4 matrica ar baitu vērtībam
        for i in range(4):  # iterē caur rindām
            for j in range(4): # iterē caur kolonnām 
                state[i][j] = self.sbox[state[i][j]] # aizvieto vērtību ar S-box vērtību
        return state

    def shift_rows(self, state):
        #Shift rows of the state
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def mix_columns(self, state):
        # Ja pirmais bits ir 1 (skaitlis ≥ 128)
        def mul_by_2(num):
            # Bīda pa kreisi un veic XOR ar 0x1B
            if num & 0x80:
                return ((num << 1) ^ 0x1B) & 0xFF
            # Citādi vienkārši bīda pa kreisi (reizina ar 2)
            return num << 1

        def mul_by_3(num):
            # Reizināšana ar 3 = reizināšana ar 2 plus pats skaitlis
            return mul_by_2(num) ^ num

        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            
            state[0][i] = mul_by_2(s0) ^ mul_by_3(s1) ^ s2 ^ s3
            state[1][i] = s0 ^ mul_by_2(s1) ^ mul_by_3(s2) ^ s3
            state[2][i] = s0 ^ s1 ^ mul_by_2(s2) ^ mul_by_3(s3)
            state[3][i] = mul_by_3(s0) ^ s1 ^ s2 ^ mul_by_2(s3)
        
        return state

    # Decryption helper methods
    def inv_sub_bytes(self, state):
       #Apply inverse S-box substitution
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
        return state

    def inv_shift_rows(self, state):
        #Inverse shift rows of the state
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def inv_mix_columns(self, state):
        #Inverse mix columns operation
        def mul(a, b):
            if b == 0x0e:
                return mul(mul(mul(a, 0x02), 0x02), 0x02) ^ mul(mul(a, 0x02), 0x02) ^ mul(a, 0x02)
            elif b == 0x0b:
                return mul(mul(mul(a, 0x02), 0x02), 0x02) ^ mul(a, 0x02) ^ a
            elif b == 0x0d:
                return mul(mul(mul(a, 0x02), 0x02), 0x02) ^ mul(mul(a, 0x02), 0x02) ^ a
            elif b == 0x09:
                return mul(mul(mul(a, 0x02), 0x02), 0x02) ^ a
            elif b == 0x02:
                if a & 0x80:
                    return ((a << 1) ^ 0x1B) & 0xFF
                return a << 1
            return a

        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]

            state[0][i] = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09)
            state[1][i] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d)
            state[2][i] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b)
            state[3][i] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e)

        return state

    def encrypt_block(self, block, iv=None):
        # Convert block to state array
        state = [[block[i + 4*j] for j in range(4)] for i in range(4)]
        
        # If IV is provided, XOR the state with IV before encryption
        if iv is not None:
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= iv[i + 4*j]
        
        # Initial AddRoundKey
        state = self.add_round_key(state, self.round_keys[:4])
        
        # Main rounds
        for round in range(1, 10):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[4*round:4*(round+1)])
        
        # Final round
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[40:])
        
        return bytes(state[i][j] for j in range(4) for i in range(4))

    def decrypt_block(self, block, iv=None):
        state = [[block[i + 4*j] for j in range(4)] for i in range(4)]
        
        # Store the input block for later XOR with IV
        input_block = [b for b in block]
        
        # Initial round
        state = self.add_round_key(state, self.round_keys[40:])
        
        # Main rounds
        for round in range(9, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_keys[4*round:4*(round+1)])
            state = self.inv_mix_columns(state)
        
        # Final round
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[:4])
        
        # XOR with IV if provided
        if iv is not None:
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= iv[i + 4*j]
        
        return bytes(state[i][j] for j in range(4) for i in range(4))

def pad_data(data):
    #PKCS7 padding
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def unpad_data(data):
    #Remove PKCS7 padding
    pad_length = data[-1]
    if pad_length < 1 or pad_length > 16:
        raise ValueError("Invalid padding")
    for i in range(1, pad_length + 1):
        if data[-i] != pad_length:
            raise ValueError("Invalid padding")
    return data[:-pad_length]

def encrypt(key, plaintext, iv=None):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long")
    
    # Convert text and key to bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, str):
        key = key.encode()
    
    # Generate random IV if not provided
    if iv is None:
        iv = os.urandom(16)
    elif isinstance(iv, str):
        iv = iv.encode()
    
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long")
    
    # Pad the data
    padded_data = pad_data(plaintext)
    
    aes = AES(list(key))
    ciphertext = b''
    previous_block = iv
    
    # Encrypt each block
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        encrypted_block = aes.encrypt_block(list(block), list(previous_block))
        ciphertext += encrypted_block
        previous_block = encrypted_block
    
    # Return IV + ciphertext in hex format
    return iv.hex() + ciphertext.hex()

def decrypt(key, ciphertext):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long")
    
    # Convert inputs to bytes
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    if isinstance(key, str):
        key = key.encode()
    
    if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    
    # Extract IV from the first block
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    aes = AES(list(key))
    plaintext = b''
    previous_block = iv
    
    # Decrypt each block
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes.decrypt_block(list(block), list(previous_block))
        plaintext += decrypted_block
        previous_block = block
    
    return unpad_data(plaintext)