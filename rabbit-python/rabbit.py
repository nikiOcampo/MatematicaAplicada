#!/usr/bin/env python3

from PIL import Image
from pwn import xor
import sys

################################### FUNCTIONS ###################################

def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

def testRabbit(): 
    # --- Official Test Vectors ---
    
    # RFC 4503 Appendix A.1 - Testing without IV Setup

    r = Rabbit(0)
    assert r.next().derive() == 0xB15754F036A5D6ECF56B45261C4AF702
    assert r.next().derive() == 0x88E8D815C59C0C397B696C4789C68AA7
    assert r.next().derive() == 0xF416A1C3700CD451DA68D1881673D696

    r = Rabbit(0x912813292E3D36FE3BFC62F1DC51C3AC)
    assert r.next().derive() == 0x3D2DF3C83EF627A1E97FC38487E2519C
    assert r.next().derive() == 0xF576CD61F4405B8896BF53AA8554FC19
    assert r.next().derive() == 0xE5547473FBDB43508AE53B20204D4C5E

    r = Rabbit(0x8395741587E0C733E9E9AB01C09B0043)
    assert r.next().derive() == 0x0CB10DCDA041CDAC32EB5CFD02D0609B 
    assert r.next().derive() == 0x95FC9FCA0F17015A7B7092114CFF3EAD
    assert r.next().derive() == 0x9649E5DE8BFC7F3F924147AD3A947428

    # RFC 4503 Appendix A.2 - Testing with IV Setup

    r = Rabbit(0, 0)
    assert r.next().derive() == 0xC6A7275EF85495D87CCD5D376705B7ED
    assert r.next().derive() == 0x5F29A6AC04F5EFD47B8F293270DC4A8D
    assert r.next().derive() == 0x2ADE822B29DE6C1EE52BDB8A47BF8F66

    r = Rabbit(0, 0xC373F575C1267E59)
    assert r.next().derive() == 0x1FCD4EB9580012E2E0DCCC9222017D6D
    assert r.next().derive() == 0xA75F4E10D12125017B2499FFED936F2E
    assert r.next().derive() == 0xEBC112C393E738392356BDD012029BA7

    r = Rabbit(0, 0xA6EB561AD2F41727)
    assert r.next().derive() == 0x445AD8C805858DBF70B6AF23A151104D
    assert r.next().derive() == 0x96C8F27947F42C5BAEAE67C6ACC35B03
    assert r.next().derive() == 0x9FCBFC895FA71C17313DF034F01551CB

    print("pass all the test")

def printHelp(errorString):
	global FILENAME
	raise ValueError('\n'+errorString +'\n\nUsage:\n    python '+ FILENAME +' <PATH> -<e/d> ' 
        + '<KEY> <IV>\n\nThe algorithm can be used interactively if no arguments are used\n')

def getData():
    global PATH, KEY, OPTION, IV
    PATH = input('Enter path of Image : ').strip('\n')
    OPTION = str(input("e to encrypt message, d to decrypt >> ").strip('\n'))
	
    if OPTION != "e" and OPTION != "d":
        raise ValueError('Invalid option Value')

    KEY = input('Enter Key for encryption/decryption of Image : ').strip('\n')
    #Should we ask for IV?
    iv_response = input('Enter IV for encryption of Image : ').strip('\n')
    if iv_response != '':
        IV = hex(int(iv_response))
    else:
        IV = None

def getShellData():
    global PATH, KEY, OPTION, IV

    try:
        PATH = sys.argv[1]
        OPTION = sys.argv[2].strip("-")
        KEY = sys.argv[3]
        if len(sys.argv) == 5 and sys.argv[4] != '':
            IV = hex(int(sys.argv[4]))
        else:
            IV = None

    except:
	    printHelp("Verify Command Usage, you may want to use no arguments and proceed interactively")

################################### GLOBAL VARIABLES ###################################

WORDSIZE = 0x100000000
A0 = 0x4D34D34D
A1 = 0xD34D34D3
A2 = 0x34D34D34
A3 = 0x4D34D34D
A4 = 0xD34D34D3
A5 = 0x34D34D34
A6 = 0x4D34D34D
A7 = 0xD34D34D3

A = [A0, A1, A2, A3, A4, A5, A6, A7]

rot08 = lambda x: ((x <<  8) & 0xFFFFFFFF) | (x >> 24)
rot16 = lambda x: ((x << 16) & 0xFFFFFFFF) | (x >> 16)

FILENAME = sys.argv[0]

################################### RABBIT CLASS ###################################


def _nsf(u, v):
    '''Internal non-linear state transition'''
    s = (u + v) % WORDSIZE
    s = s * s
    return (s ^ (s >> 32)) % WORDSIZE

class Rabbit:

    def __init__(self, key, iv = None):
        '''Initialize Rabbit cipher using a 128 bit integer/string'''
        
        if isinstance(key, str):
            # interpret key string in big endian byte order
            if len(key) < 16:
                key = '\x00' * (16 - len(key)) + key
            # if len(key) > 16 bytes only the first 16 will be considered
            k = [ord(key[i + 1]) | (ord(key[i]) << 8)
                 for i in range(14, -1, -2)]
        else:
            # k[0] = least significant 16 bits
            # k[7] = most significant 16 bits
            k = [(key >> i) & 0xFFFF for i in range(0, 128, 16)]
            
        # State and counter initialization
        x = [(k[(j + 5) % 8] << 16) | k[(j + 4) % 8] if j & 1 else
             (k[(j + 1) % 8] << 16) | k[j] for j in range(8)]
        c = [(k[j] << 16) | k[(j + 1) % 8] if j & 1 else
             (k[(j + 4) % 8] << 16) | k[(j + 5) % 8] for j in range(8)]
        
        self.x = x
        self.c = c
        self.b = 0
        self._buf = 0           # output buffer
        self._buf_bytes = 0     # fill level of buffer
        
        #iterate four times
        for _ in range(4):
            self.next()

        #reinitialized counters
        for j in range(8):
            c[j] ^= x[(j + 4) % 8]
        
        self.start_x = self.x[:]    # backup initial key for IV/reset
        self.start_c = self.c[:]
        self.start_b = self.b

        if iv != None:
            self.set_iv(iv)

    def reset(self, iv = None):
        '''Reset the cipher and optionally set a new IV (int64 / string).'''
        
        self.c = self.start_c[:]
        self.x = self.start_x[:]
        self.b = self.start_b
        self._buf = 0
        self._buf_bytes = 0
        if iv != None:
            self.set_iv(iv)

    def set_iv(self, iv):
        '''Set a new IV (64 bit integer / bytestring).'''

        if isinstance(iv, str):
            i = 0
            for c in iv:
                i = (i << 8) | ord(c)
            iv = i

        c = self.c
        i0 = iv & 0xFFFFFFFF
        i2 = iv >> 32
        i1 = ((i0 >> 16) | (i2 & 0xFFFF0000)) % WORDSIZE
        i3 = ((i2 << 16) | (i0 & 0x0000FFFF)) % WORDSIZE
        
        c[0] ^= i0
        c[1] ^= i1
        c[2] ^= i2
        c[3] ^= i3
        c[4] ^= i0
        c[5] ^= i1
        c[6] ^= i2
        c[7] ^= i3

        for _ in range(4):
            self.next()        

    def next(self):
        '''Proceed to the next internal state'''
        
        c = self.c
        x = self.x
        b = self.b
        for i in range(8):
            temp = c[i] + A[i] + b
            b = temp // WORDSIZE
            c[i] = temp % WORDSIZE
        
        g = [_nsf(x[j], c[j]) for j in range(8)]
        
        x[0] = (g[0] + rot16(g[7]) + rot16(g[6])) % WORDSIZE
        x[1] = (g[1] + rot08(g[0]) + g[7]) % WORDSIZE
        x[2] = (g[2] + rot16(g[1]) + rot16(g[0])) % WORDSIZE
        x[3] = (g[3] + rot08(g[2]) + g[1]) % WORDSIZE
        x[4] = (g[4] + rot16(g[3]) + rot16(g[2])) % WORDSIZE
        x[5] = (g[5] + rot08(g[4]) + g[3]) % WORDSIZE
        x[6] = (g[6] + rot16(g[5]) + rot16(g[4])) % WORDSIZE
        x[7] = (g[7] + rot08(g[6]) + g[5]) % WORDSIZE
        
        self.b = b
        return self


    def derive(self):
        '''Derive a 128 bit integer from the internal state'''
        
        x = self.x
        return ((x[0] & 0xFFFF) ^ (x[5] >> 16)) | \
               (((x[0] >> 16) ^ (x[3] & 0xFFFF)) << 16)| \
               (((x[2] & 0xFFFF) ^ (x[7] >> 16)) << 32)| \
               (((x[2] >> 16) ^ (x[5] & 0xFFFF)) << 48)| \
               (((x[4] & 0xFFFF) ^ (x[1] >> 16)) << 64)| \
               (((x[4] >> 16) ^ (x[7] & 0xFFFF)) << 80)| \
               (((x[6] & 0xFFFF) ^ (x[3] >> 16)) << 96)| \
               (((x[6] >> 16) ^ (x[1] & 0xFFFF)) << 112)

    
    def keystream(self, n):
        '''Generate a keystream of n bytes'''
        
        res = ""
        b = self._buf
        j = self._buf_bytes
        next = self.next
        derive = self.derive
        
        for i in range(n):
            if not j:
                j = 16
                next()
                b = derive()
            res += chr(b & 0xFF)
            j -= 1
            b >>= 1

        self._buf = b
        self._buf_bytes = j
        return res


    def encrypt(self, data):
        '''Encrypt/Decrypt data of arbitrary length.'''
        
        res = ""
        b = self._buf
        j = self._buf_bytes
        next = self.next
        derive = self.derive

        for c in data:
            if not j:   # empty buffer => fetch next 128 bits
                j = 16
                next()
                b = derive()
            res += chr(ord(c) ^ (b & 0xFF))
            j -= 1
            b >>= 1
        self._buf = b
        self._buf_bytes = j
        return res

    decrypt = encrypt
        
    
################################### MAIN PROGRAM ###################################

#testRabbit() this run test vectors to check if the rabbit cipher is ok

try:
    if(len(sys.argv) == 1):
        getData()
    else:
        getShellData()
except (ValueError, IndexError) as err:
    print(err.args[0])
    sys.exit(1)

# if IV == None:
#     IV = 0xA6EB561AD2F41727

r = Rabbit(KEY, IV)

size = 16 #blocksize separation apply on image

if OPTION == 'e':
    original_image = Image.open(PATH)
    original_image_array = bytearray(original_image.tobytes())
    original_image_matrix = list(split(original_image_array,size))

    image_format = original_image.format.lower()

    if(image_format == 'png'):
        for i in range(size//2):
            aux = original_image_matrix[i]
            original_image_matrix[i] = original_image_matrix[size-1-i]
            original_image_matrix[size-1-i] = aux

    s = r.keystream(len(original_image_array)).encode('ISO-8859-1')

    result_image = b''.join(original_image_matrix)

    encripted_bytes = xor(result_image, s)

    result = Image.frombytes(original_image.mode, original_image.size, encripted_bytes)

    encripted_filename = 'encrypted.' + image_format
        
    result.save("./result/" + encripted_filename)

elif OPTION == 'd': 
    encripted_image = Image.open(PATH)
    encripted_image_array = bytearray(encripted_image.tobytes())

    s = r.keystream(len(encripted_image_array)).encode('ISO-8859-1')

    decripted_bytes = xor(encripted_image.tobytes(), s)

    decripted_image_matrix = list(split(bytearray(decripted_bytes),size))

    image_format = encripted_image.format.lower()

    if(image_format == 'png'):
        for i in range(size//2):
            aux = decripted_image_matrix[size-1-i]
            decripted_image_matrix[size-1-i] = decripted_image_matrix[i]
            decripted_image_matrix[i] = aux

    result_image = b''.join(decripted_image_matrix)

    result = Image.frombytes(encripted_image.mode, encripted_image.size, result_image)

    decripted_filename = "decrypted." + image_format
        
    result.save("./result/" + decripted_filename)
else:
    print("Unsupported option")

print("Completed operation")
    