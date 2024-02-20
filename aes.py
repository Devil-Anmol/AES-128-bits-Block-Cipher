import numpy as np
import hashlib
import galois

g = galois.GF(2**8, irreducible_poly=[1,0,0,0,1,1,0,1,1])       

class AES:
    __key="0f1571c947d9e8590cb7add6af7f6798"
    __plaintext = ""
    __roundkey=[]
    __ciphertext = ""
    __aes_sbox = [
        [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
            '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
        [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
            'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
        [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
            '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
        [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
            '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
        [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
            '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
        [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
            '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
        [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
            '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
        [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
            'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
        [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
            'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
        [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
            '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
        [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
            'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
        [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
            '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
        [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
            'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
        [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
            '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
        [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
            '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
        [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
            '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
    ]

    __reverse_aes_sbox = [
        [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
            'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
        [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
            '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
        [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
            'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
        [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
            '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
        [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
            'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
        [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
            '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
        [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
            'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
        [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
            'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
        [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
            '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
        [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
            'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
        [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
            '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
        [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
            '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
        [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
            'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
        [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
            '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
        [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
            'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
        [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
            'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
    ]

    __mix_column = np.array([
            [2,3,1,1],
            [1,2,3,1],
            [1,1,2,3],
            [3,1,1,2]
            ])
    
    __inv_mix_column = np.array([
            [int('0e',16),int('0b',16),int('0d',16),int('09',16)],
            [int('09',16),int('0e',16),int('0b',16),int('0d',16)],
            [int('0d',16),int('09',16),int('0e',16),int('0b',16)],
            [int('0b',16),int('0d',16),int('09',16),int('0e',16)]
            ])
    
    __text = ""
    def __init__(self):
        self.__round_key(self.__key,10,1)
        return
    
    def encode(self,string):
        hash = self.__hashing(string)
        self.__plaintext = string + hash + "#"*((16 - len(string)%16)%16)
    
    def __hashing(self,text):
        hash = hashlib.sha256(text.encode())
        return hash.hexdigest()

    def __sub_box(self,byte):
        x = byte >> 4
        y = byte & 15
        return self.__aes_sbox[x][y]

    def __inv_sub_box(self,byte):
        x = byte >> 4
        y = byte & 15
        return self.__reverse_aes_sbox[x][y]
    
    def __substitute(self,array):
        for i in range(4):
            for j in range(4):
                array[i][j] = self.__sub_box(array[i][j])
        return array
    
    def __inv_substitute(self,array):
        for i in range(4):
            for j in range(4):
                array[i][j] = self.__inv_sub_box(array[i][j])
        return array
    
    # Key expansion
    def __round_key(self,key,round,hex=0):
        Rcon = np.array([1,2,4,8,16,32,64,128,27,54])
        if(hex == 0):
            key = key[:16]
            key1 = [ord(x) for x in key]
            key = np.array([np.array(key1[i:i+4]) for i in range(0,16,4)])
        else:
            key1 = key[:]
            key = np.array([np.array(np.array([int(key1[i:i+2],16),int(key1[i+2:i+4],16),int(key1[i+4:i+6],16),int(key1[i+6:i+8],16)])) for i in range(0,32,8)])

        for i in range(round):
            g = np.roll(key[-1],-1)
            shift = np.array([self.__sub_box(x) for x in g])
            shift[0] ^= Rcon[i]
            shift = np.array(shift)
            w = np.zeros((4,4), dtype = np.int64)
            w[0] = shift ^ key[-4]
            w[1] = w[0] ^ key[-3]
            w[2] = w[1] ^ key[-2]
            w[3] = w[2] ^ key[-1]
            key= np.append(key,w,axis = 0)

        self.__roundkey = key
        return

    def __mix_column_func(self,w):
        # w = np.transpose(w)
        # array = np.zeros((4,4),dtype=np.int64)
        # for i in range(4):
        #     for j in range(4):
        #         array[i][j] = np.dot(g(mix_column[i]),g(w[j]))
        array = g.dot(g(self.__mix_column),g(w))
        return array
    
    def __inv_mix_column_func(self,w):
        # w = np.transpose(w)
        # array = np.zeros((4,4),dtype=np.int64)
        # for i in range(4):
        #     for j in range(4):
        #         array[i][j] = np.dot(g(mix_column[i]),g(w[j]))
        array = g.dot(g(self.__inv_mix_column),g(w))
        return array
    
    def __rotate_rows(self,w,n=-1):
        w[1] = np.roll(w[1],n)
        w[2] = np.roll(w[2],2*n)
        w[3] = np.roll(w[3],3*n)
        return w
    
    def __addRoundKey(self,key,w):
        array = key^w
        return array
    
    def __slicing(self,text,hex=0):
        if(hex==0):
            w = [ord(x) for x in text]
            words = [w[i:i+4] for i in range(0,len(w),4)]
            return words
        else:
            words = []
            w = text
            [words.append([int(w[i:i+2],16),int(w[i+2:i+4],16),int(w[i+4:i+6],16),int(w[i+6:i+8],16)]) for i in range(0,len(w),8)]
            return words
        
    def __process(self,text):
        array = self.__addRoundKey(self.__roundkey[:4].T,text)
        for i in range(1,10):
            array = self.__substitute(array)
            array = self.__rotate_rows(array)
            array = self.__mix_column_func(array)
            array = self.__addRoundKey(self.__roundkey[i*4:(i+1)*4].T,array)
        array = self.__substitute(array)
        array = self.__rotate_rows(array)
        array = self.__addRoundKey(self.__roundkey[40:].T,array)
        return array
    
    def __inv_process(self,text):
        array = self.__addRoundKey(self.__roundkey[40:].T,text)
        for i in range(9,0,-1):
            array = self.__rotate_rows(array,1)
            array = self.__inv_substitute(array)
            key = self.__roundkey[i*4:(i+1)*4].T
            array = self.__addRoundKey(key,array)
            array = self.__inv_mix_column_func(array)
        array = self.__rotate_rows(array,1)
        array = self.__inv_substitute(array)
        array = self.__addRoundKey(self.__roundkey[:4].T,array)
        return array

    def encryption(self):
        self.__text = self.__slicing(self.__plaintext,0)
        n = int(len(self.__text)/4)
        e = []
        for i in range(n):
            w = self.__text[i*4:(i+1)*4]
            w = np.transpose(w)
            e.extend(self.__process(w).T)
            
        t = ""
        for i in e:
            for j in i:
                k = str(hex(j)[2:])
                if(len(k)==1):
                    k = "0" + k
                t+=k
        
        self.__ciphertext = t
        
    def cipher(self):
        return self.__ciphertext
    
    def decrypt(self,ciphertext):
        word = self.__slicing(ciphertext,1)
        n = int(len(word)/4)
        e =[]
        for i in range(n):
            w = word[i*4:(i+1)*4]
            w = np.transpose(w)
            e.extend(self.__inv_process(w).T)

        t = ""
        for i in e:
            for j in i:
                k = chr(j)
                t+=k
        message = t.rstrip("#")
        size = len(message)
        hash = message[size-64:]
        plaintext = message[:size-64]
        check = self.__hashing(plaintext)
        if(check==hash):
            return plaintext
        return "Wrong"
    
a = AES()       # Key is hardcoded can be changed in the class AES 
a.encode("My name is Mr. Nobody") # encode the string to encrypt with the AES
a.encryption()
cipher = a.cipher()
print(cipher)
print(a.decrypt(cipher))
