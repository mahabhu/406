# !pip install BitVector

from BitVector import *
import codecs
import copy
import string
import random
import time
import socket 
import base64

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

AES_modulus = BitVector(bitstring='100011011')
keyRounds = {128 : 10, 192 : 12, 256 : 14}

def printHexMatrix(matrix):
    for i in range(4):
        for j in range(len(matrix[0])):
            print(matrix[i][j].get_bitvector_in_hex(),end=' ')
        print()
    print()

def getInitializationVector(aesLen):
    ascii_characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(ascii_characters) for _ in range(aesLen//8))

def printHex(hexString):
    str = ""
    # print("--------",len(hexString))
    for i in range(0,len(hexString),2):
        str += hexString[i:i+2]+" "
    return str

######################### conversion functions

def asciiStringToHexVector(asciiString):
    vector = []
    for asciiChar in asciiString:
        hs = hex(ord(asciiChar))[2:]
        while len(hs)<2:
            hs = '0'+hs
        # hs = asciiChar.encode().hex()
        vector.append(hs) 
    return vector

def hexVectorToHexMatrix(hexVector):
    hexMatrix = []
    length = len(hexVector)
    for i in range(4):
        vector = []
        for j in range(i,length,4):
            vector.append(BitVector(hexstring=hexVector[j]))
        hexMatrix.append(vector)
    return hexMatrix

def matrixToVector(matrix):
    ret = []
    for j in range(len(matrix[0])):
        for i in range(len(matrix)):
            ret.append(matrix[i][j])
    return ret


def resizeKey(aesLen,key):
    keyLen = aesLen//8
    key = key[:keyLen]
    key = key.ljust(keyLen, '_')
    return key

def hexVectorToHexString(hexVector):
    ret = []
    for hex in hexVector:
        ret.append(hex.get_bitvector_in_hex())
    return ret

def hexMatrixVectorToHexStringVector(cipherHexMatrixVector):
    ret = []
    for cipherHexMatrix in cipherHexMatrixVector:
        cipherBlockVector = matrixToVector(cipherHexMatrix)
        block = hexVectorToHexString(cipherBlockVector)
        block = ''.join(block)
        ret.append(block)
    return ret

def hexStringVectorToHexMatrixVector(hexStringVector):
    ret = []
    for hexString in hexStringVector:
        hexVector = []
        for i in range(0,len(hexString),2):
            hexVector.append(hexString[i:i+2])
        hexMatrix = hexVectorToHexMatrix(hexVector)
        ret.append(hexMatrix)
    return ret

def hexToASCII(hexString):
    binaryString = codecs.decode(hexString, 'hex')
    return str(binaryString,"ISO-8859-1") 

def hexVectorToAsciiVector(asciiVector):
    ret = []
    for ascii in asciiVector:
        ret.append(ascii.get_bitvector_in_ascii())
    return ret

def addPadding(aesLen,textHexVector):
    blockSize = aesLen//8
    textLen = len(textHexVector)
    paddingCount = textLen%blockSize
    if paddingCount==0:
        for i in range(blockSize):
            textHexVector.append("00")
    else:
        paddingCount = blockSize-paddingCount
        str = hex(paddingCount)[2:]
        if len(str)<2 :
            str = "0"+str
        
        while(paddingCount != 0):
            textHexVector.append(str)
            paddingCount-=1
    return textHexVector

def rmvPadding(aesLen,textHexVector):
    blockSize = aesLen//8
    textLen = len(textHexVector)
    paddingCount = int(textHexVector[textLen-1])
    if paddingCount==0:
        paddingCount=blockSize
    textHexVector = textHexVector[:textLen-paddingCount]
    return textHexVector

######################### aes unit functions

def shiftVector(vector,m):
    newVector = vector[:]
    n = len(vector)
    for i in range(0,n):
        newVector[i] = vector[(i+n+m)%n]
    return newVector

def shiftMatrix(matrix,left=True): 
    for i in range(4):
        if left:
            matrix[i] = shiftVector(matrix[i],i)
        else:
            matrix[i] = shiftVector(matrix[i],-i)
    return matrix

def subBytesVector(vector):
    ret = []
    for elem in vector:
        # print(elem.intValue())
        ret.append(BitVector(intVal=Sbox[elem.intValue()], size=8))
    return ret

def invSubBytesVector(vector):
    ret = []
    for elem in vector:
        ret.append(BitVector(intVal=InvSbox[elem.intValue()], size=8))
    return ret

def subBytesMatrix(matrix):
    ret = matrix[:][:]
    for i in range(len(ret)):
        ret[i] = subBytesVector(ret[i])
    return ret

def invSubBytesMatrix(matrix):
    ret = matrix[:][:]
    for i in range(len(ret)):
        ret[i] = invSubBytesVector(ret[i])
    return ret

def xorVector(vector1,vector2):
    ret = []
    for i in range(len(vector1)):
        ret.append(vector1[i]^vector2[i])
    return ret

def xorMatrix(matrix1,matrix2):
    ret = []
    for i in range(len(matrix1)):
        ret.append(xorVector(matrix1[i],matrix2[i]))
    return ret

def g(vector,roundConst):
    ret = shiftVector(vector,1)
    ret = subBytesVector(ret)
    k0 = BitVector(hexstring="00")
    ret = xorVector(ret,[roundConst,k0,k0,k0])
    return ret

def keyExpansion(aesLen, key):
    keys = []
    key = asciiStringToHexVector(resizeKey(aesLen,key))
    keys.append(hexVectorToHexMatrix(key))
    columnNo = aesLen//32

    roundConst = BitVector(hexstring="01")
    for round in range(1,keyRounds[aesLen]+1):
        lastVector = []
        for i in range(4):
            lastVector.append(keys[round-1][i][columnNo-1])
        lastVector = g(lastVector,roundConst)
        currentKey = copy.deepcopy(keys[round-1])
        for j in range(columnNo):
            for i in range(4):
                if j==0:
                    currentKey[i][j]=currentKey[i][j]^lastVector[i]
                else:
                    currentKey[i][j]=currentKey[i][j]^currentKey[i][j-1]

        keys.append(currentKey)


        k2 = BitVector(hexstring="02")
        k11B = BitVector(hexstring="11B")
        k80 = BitVector(hexstring="80")
        # if roundConst<k80:
        roundConst = k2.gf_multiply_modular(roundConst, AES_modulus, 8)
        # else:
        #     roundConst = k2.gf_multiply_modular(roundConst, AES_modulus, 8)
        #     roundConst ^= k11B

    return keys

def mixColumns(aesLen,matrix):
    columnNo = aesLen//32
    ret = []
    for i in range(4):
        ret.append([BitVector(intVal=0, size=8)]*columnNo)
    for i in range(4):
        for j in range(columnNo):
            for k in range(4):
                ret[i][j] = ret[i][j]^Mixer[i][k].gf_multiply_modular(matrix[k][j], AES_modulus, 8)

    return ret

def invMixColumns(aesLen,matrix):
    columnNo = aesLen//32
    ret = []
    for i in range(4):
        ret.append([BitVector(intVal=0, size=8)]*columnNo)
    for i in range(4):
        for j in range(columnNo):
            for k in range(4):
                ret[i][j] = ret[i][j]^InvMixer[i][k].gf_multiply_modular(matrix[k][j], AES_modulus, 8)

    return ret

def encryptBlock(aesLen, text, iv, keys):
    matrix = hexVectorToHexMatrix(text)
    matrix = xorMatrix(matrix,iv)
    matrix = xorMatrix(matrix,keys[0])
    for round in range(1,keyRounds[aesLen]+1):
        matrix = subBytesMatrix(matrix)
        matrix = shiftMatrix(matrix,True)
        if round!=keyRounds[aesLen]:
            matrix = mixColumns(aesLen,matrix)
        matrix = xorMatrix(matrix,keys[round])
    return matrix

def decryptBlock(aesLen, cipherHexMatrix, iv, keys):
    matrix = xorMatrix(cipherHexMatrix,keys[0])
    for round in range(1,keyRounds[aesLen]+1):
        matrix = invSubBytesMatrix(matrix)
        matrix = shiftMatrix(matrix,False)
        matrix = xorMatrix(matrix,keys[round])
        if round!=keyRounds[aesLen]:
            matrix = invMixColumns(aesLen,matrix)
    matrix = xorMatrix(matrix,iv)
    return matrixToVector(matrix)

def encryptText(aesLen,textHexVector,iv,keys):
    textHexVector = addPadding(aesLen,textHexVector)
    blockSize = aesLen//8
    textLen = len(textHexVector)
    ret = []
    iv = hexVectorToHexMatrix(asciiStringToHexVector(iv))
    for i in range(0,textLen,blockSize):
        # print(i/blockSize," out of ",textLen/blockSize," done")
        matrix = encryptBlock(aesLen,textHexVector[i:i+blockSize],iv,keys)
        iv = matrix
        ret.append(matrix)
    return ret # returns array of matrices

def decryptText(aesLen,cipherHexMatrixVector,iv,keys):
    ret = []
    iv = hexVectorToHexMatrix(asciiStringToHexVector(iv))
    keys.reverse()
    for cipherHexMatrix in cipherHexMatrixVector:
        ret.extend(decryptBlock(aesLen,cipherHexMatrix,iv,keys))
        iv = cipherHexMatrix
    keys.reverse()
    return ret


def E_aescbc(aesLen,text,iv,key):
    start_time = time.time()


    textHexVector = asciiStringToHexVector(text)
    keys = keyExpansion(aesLen,key)

    key_schedule_time = time.time() - start_time

    start_time = time.time()

    cipherHexMatrixVector = encryptText(aesLen,textHexVector,iv,keys)
    cipherHexStringVector = hexMatrixVectorToHexStringVector(cipherHexMatrixVector)

    encryption_time = time.time() - start_time


    return cipherHexStringVector,key_schedule_time,encryption_time

def D_aescbc(aesLen,hexStringVector,iv,key):
    keys = keyExpansion(aesLen,key)
    hexMatrixVector = hexStringVectorToHexMatrixVector(hexStringVector)
    decipherHexVector = decryptText(aesLen,hexMatrixVector,iv,keys)
    
    decipherHexVector = rmvPadding(aesLen,decipherHexVector)
    return decipherHexVector

def receiveEncrypted(c,AES_LEN,key,show=True):
    print("DECRYPTING RECEIVE---")
    blockSize = AES_LEN//8
    cipherText = c.recv(1024).decode()
    iv = cipherText[:blockSize]
    cipherText = cipherText[blockSize:]
    # print(cipherText)
    hexStringVector = []
    for i in range(0,len(cipherText),AES_LEN//8):
        hexString = ''.join(asciiStringToHexVector(cipherText[i:i+AES_LEN//8]))
        hexStringVector.append(hexString)

    decipherHexVector = D_aescbc(AES_LEN,hexStringVector,iv,key)
    decipherText = ''.join(hexVectorToAsciiVector(decipherHexVector))
    if show:
        print("key       : ",key)
        print("iv        : ",iv)
        print("text      : ",decipherText)
        print("cipherText: ",cipherText)
    print("DONE RECEIVING---")
    return cipherText,decipherText

def sendEncrypted(c,AES_LEN,text,iv,key,show=True):
    print("ENCRYPTING SEND---")
    hexStringVector,key_time,enc_time= E_aescbc(AES_LEN,text,iv,key)
    cipherText = hexToASCII(''.join(hexStringVector))
    c.send((iv+cipherText).encode())
    if show:
        print("key       : ",key)
        print("iv        : ",iv)
        print("text      : ",text)
        print("cipherText: ",cipherText)
    print("DONE SENDING---")
    return cipherText

def fileToAsciiString(filePath):
    try:
        with open(filePath, 'rb') as file:
            binaryData = file.read()
            asciiString = base64.b64encode(binaryData).decode('ascii')
            return asciiString
    except FileNotFoundError:
        return "File not found"
    
def asciiStringToFile(asciiString, outputFilePath):
    try:
        binaryData = base64.b64decode(asciiString.encode('ascii'))
        with open(outputFilePath, 'wb') as file:
            file.write(binaryData)
        return "File successfully created: " + outputFilePath
    except Exception as e:
        return "Error occurred: " + str(e)

def receiveFile(c,AES_LEN,key,filePath):
    print("RECEIVING FILE---")
    cipherText,decipherText = receiveEncrypted(c,AES_LEN,key,False)
    result = asciiStringToFile(decipherText, filePath)
    return cipherText,decipherText,result

def sendFile(c,AES_LEN,iv,key,filePath):
    print("SENDING FILE---")
    text = fileToAsciiString(filePath)
    # print(len(text)%(AES_LEN//8))
    cipherText = sendEncrypted(c,AES_LEN,text,iv,key,False) 
    return cipherText

def main():
    AES_LEN = 192
    key  = "BUET CSE19 Batch19 Batch"
    text = "Never Gonna GiveBUET CSEver Gonna GiveBUET CSE"
    iv = getInitializationVector(AES_LEN)
    

    hexStringVector,key_time,enc_time= E_aescbc(AES_LEN,text,iv,key)
    start_time = time.time()
    decipherHexVector = D_aescbc(AES_LEN,hexStringVector,iv,key)
    dec_time = time.time() - start_time

    print("Key:")
    print("In ASCII: ",key)
    print("In HEX: ",printHex(''.join(asciiStringToHexVector(key))))
    print("")

    print("Plain Text:")
    print("In ASCII: ",text)
    print("In HEX: ",printHex(''.join(asciiStringToHexVector(text))))
    print("")
    
    print("Initialization Vector:")
    print("In ASCII: ",iv)
    print("In HEX: ",printHex(''.join(asciiStringToHexVector(iv))))
    print("")

    print("Ciphered Text:")
    print("In HEX: ",printHex(''.join(hexStringVector)))
    print("In ASCII: ",hexToASCII(''.join(hexStringVector)))
    print("")

    print("Deciphered Text:")
    print("In HEX: ",printHex(''.join(hexVectorToHexString(decipherHexVector))))
    print("In ASCII: ",''.join(hexVectorToAsciiVector(decipherHexVector)))
    print("")

    print("Execution Time Details: ")
    print("Key Schedule Time : ",round(key_time*1000,3),"ms")
    print("Encryption Time : ",round(enc_time*1000,3),"ms")
    print("Decryption Time : ",round(dec_time*1000,3),"ms")

    # print("ke back : ", hexToASCII(stringToHexVector(key)))

# main()