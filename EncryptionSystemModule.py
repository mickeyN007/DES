__author__ = "Michael Oduah\n Babatunde Adesoye"
__date__ = "10/8/2016"

from RoundKeyGeneratorModule import *
class EncryptionSystem:
    """
    Encryption System.
    This system is a subsystem of the DES system. The Encryption system
    is made up of a class "EncryptionSystem" and seven functions.
    Altogether, this system produces 16 keys. These keys are used to encrypt data.

    @param:  text
    @return: encrypted text
    """
    
    def __init__(self,pTxt):
        self.__sBoxes = [
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ],
            [	[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11,15],
		[0, 14, 7, 11, 10 ,4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
            ],
            [	[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12] 
            ],
            [	[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
            ],
            [	[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
            ],
            [	[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] 
            ],
            [	[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
            ],
            [	[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
            ]
        ]

        self.__eKey = ""
        self.__pTxt = pTxt
        self.__packets = []
        
        EncryptionSystem.toBin(self)
        self.__eRounds = len(self.__eKey) // 64
        EncryptionSystem.toPackets(self)

    def toBin(self):
        """
        This method converts the private attribute key to binary

        @param:  self
        @return: void (sets private attribute key to binary)
        """
        self.__eKey += "".join(str(bin(ord(x))).replace("b", "") for x in self.__pTxt)

        # pad if needed
        if len(self.__eKey) % 64 != 0:
            self.__eKey = ("0" * (64 - (len(self.__eKey) % 64)))+ self.__eKey

    def toPackets(self):
        # initializations
        start = 0
        end = 64

        for i in range(self.__eRounds):
            self.__packets.append(self.__eKey[start:end])
            start = end
            end = end + 64

    def initialPermutation(self, eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, \
                   12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, \
                   32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, \
                   43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, \
                   63, 55, 47, 39, 31, 23, 15, 7 \
                   ]

        # save list version of key for easier processing
        keyList = list(eKey)

        # create new list to store new key
        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        newKey = EncryptionSystem.listToString(self,tmpList)

        return newKey

    def finalPermutation(self, eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, \
                   12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, \
                   32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, \
                   43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, \
                   63, 55, 47, 39, 31, 23, 15, 7 \
                   ]

        # save list version of key for easier processing
        keyList = list(eKey)

        # create new list to store new key
        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        newKey = EncryptionSystem.listToString(self,tmpList)

        return newKey

    def expand(self, eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, \
                   8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, \
                   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, \
                   24, 25, 26, 27, 28, 29, 28, 29, 31, 31, 32, 1]

        # get 32 right most bit
        tmpKey = eKey[32:]

        # save only other half --32 left most bit
        eKey = eKey[0:32]
        
        # save list version of key for easier processing
        keyList = list(tmpKey)

        # create new list to store new key
        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        eKey += EncryptionSystem.listToString(self,tmpList)

        return eKey

    def xOr(self,eKey, rKey):
        # initializations
        newKey = ""
        indx = 0
        
        # get 48 right most bit
        tmpKey = eKey[48:]

        # save only other half --32 left most bit
        eKey = eKey[0:48]

        # do an XOR operation for each bit
        for i in tmpKey:
            newKey += str(int(i) ^ int(rKey[indx]))
            indx += 1
        eKey += newKey
        
        return eKey

    def toDec(binN):
        print("d: ", binN)
        # declarations
        counter = 0
        decimal = 0
        binArray = list(binN)
        # reverse list
        binArray.reverse()

        # convert to decimal
        for i in binArray:
            print(i)
            if i == "1":
                decimal += (2**counter)

        return decimal

    def toBinB(self,decN):
        q = int(decN)
        binN = []
        while q > 0:
            binN.append(q % 2)
            q = q // 2

        # reverse and convert back to string
        binN.reverse()
        eKey = EncryptionSystem.listToString(self,binN)
        # add padding if necessary
        eKey = "0" * (4 - len(eKey)) + eKey
        return eKey
            
    def sBoxPassing(self,eKey):
        # get 32 right most bit
        tmpKey = eKey[32:]

        # save only other half --32 left most bit
        eKey = eKey[0:32]
        
        # save list version of key for easier processing
        keyList = list(tmpKey)
        # split bits into eight equal parts
        splitBits = [tmpKey[0:6],tmpKey[6:12],tmpKey[12:18],tmpKey[18:24],tmpKey[24:30],tmpKey[30:36],tmpKey[36:42],tmpKey[42:48]]

        for i in range(8):
            # convert to decimal
            row = EncryptionSystem.toDec(splitBits[i][0] + splitBits[i][5])
            col = EncryptionSystem.toDec(splitBits[i][1:5])

            # get value from sbox
            sBoxVal = self.__sBoxes[i][row][col]
            eKey += EncryptionSystem.toBinB(self,sBoxVal)
        return eKey
        
    def straightPBox(self,eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [16, 7, 20, 21, 29, 12, 28, 17, \
                   1, 15, 23, 26, 5, 18, 31, 10, \
                   2, 8, 24, 14, 32, 27, 3, 9, \
                   19, 13, 30, 6, 22, 11, 4, 25]

        # get 32 right most bit
        tmpKey = eKey[32:]

        # save only other half --32 left most bit
        eKey = eKey[0:32]

        # save list version of key for easier processing
        keyList = list(tmpKey)

        # create new list to store new key
        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        eKey += EncryptionSystem.listToString(self,tmpList)

        return eKey

    def swap(self,eKey):
        a = eKey[0:32]
        b = eKey[32:]

        return a+b

    def encrypt(self,keys):
        #
        for encryptionN in range(self.__eRounds):
            eKey = self.__packets[encryptionN]
            eKey = EncryptionSystem.initialPermutation(self,eKey)
            for rounD in range(16):
                eKey = EncryptionSystem.expand(self,eKey)
                eKey = EncryptionSystem.xOr(self,eKey,keys[rounD])
                eKey = EncryptionSystem.sBoxPassing(self,eKey)
                eKey = EncryptionSystem.straightPBox(self,eKey)
                eKey = EncryptionSystem.swap(self,eKey)
                
                
        return EncryptionSystem.toHexDec(self,eKey)

    def toHexDec(self,eKey):
        # declarations
        start = 0
        end = 4
        hexD = ""
        # convert to hexDec
        print(eKey)
        while end <= 64:
            dec = EncryptionSystem.toDec(eKey[start:end])
            print(dec)
            print(eKey[start:end])
            if dec >= 10:
                if dec == 10:
                    hexD += "A"
                elif dec == 11:
                    hexD += "B"
                elif dec == 12:
                    hexD += "C"
                elif dec == 13:
                    hexD += "D"
                elif dec == 14:
                    hexD += "E"
                else:
                    hexD += "F"
            else:
                hexD += str(dec)
            start = end
            end = end * 2

        return hexD
            
        
    def listToString(self,keyList):
        """
        This method converts a list to a string

        @param:  list of keys
        @return: string type of list of keys
        """
        # convert list to string
        keyString = ""
        for i in keyList:
            keyString += str(i)

        return keyString

# get data
#data = input("Enter data you wish to encrypt: ")
#key = input("Enter key to be used for encryption: ")

# create systems
kg = RoundKeyGenerator("securitybbb")        
es = EncryptionSystem("security")
#kg = RoundKeyGenerator(data)        
#es = EncryptionSystem(key)

# generate keys
keys = kg.generate()

# encrypt data
encryptedData = es.encrypt(keys)

# display info
print("Data: ", "security")#data)
print()
print("Encrypted Data: ", encryptedData, len(encryptedData))

