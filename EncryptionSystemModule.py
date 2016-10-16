__author__ = "Michael Oduah\n Babatunde Adesoye"
__date__ = "10/8/2016"

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
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, \
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, \
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, \
            ],
            [
            ],
            [
            ],
            [
            ],
            [
            ],
            [
            ],
            [
            ],
            [
            ],
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
            end = end * 2

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

    def expand(self, eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, \
                   10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, \
                   63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, \
                   14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

        # get 32 right most bit
        tmpKey = eKey[31:]

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
        tmpKey = eKey[47:]

        # save only other half --32 left most bit
        eKey = eKey[0:48]

        # do an XOR operation for each bit
        for i in tmpKey:
            newKey += int(i) ^ int(rKey[indx])
            indx += 1
        eKey += newKey
        
        return eKey

    def sBoxPassing(self,eKey,):
        # get 48 right most bit
        tmpKey = eKey[47:]

        # save only other half --32 left most bit
        eKey = eKey[0:48]
        
        # save list version of key for easier processing
        keyList = list(tmpKey)

        # split bits into eight equal parts
        splitBits = [tmpKey[0:6],tmpKey[6:12],tmpKey[12:18],tmpKey[18:24],tmpKey[24:30],tmpKey[30:36],tmpKey[36:42],tmpKey[42:48],]

        # create new list to store new key
        tmpList = []

        for i in self.__sBoxes[]:
            tmpList.append(keyList[i - 1])

        # convert back to string
        eKey += EncryptionSystem.listToString(self,tmpList)

        return eKey
        
    def straightPBox(self,eKey):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, \
                   10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, \
                   63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, \
                   14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

        # save list version of key for easier processing
        keyList = list(self.__key)

        # create new list to store new key
        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        newKey = EncryptionSystem.listToString(self,tmpList)

        return newKey

    def encrypt(self,keys):
        #
        for encryptionN in range(self.__eRounds):
            eKey = self.__packets[encryptionN]
            #eKey = EncryptionSystem.initialPermutation(self,eKey)
            for rounD in range(16):
                eKey = EncryptionSystem.expand(self,eKey)
                eKey = EncryptionSystem.xOr(self,eKey,keys[roundD])
                eKey = EncryptionSystem.sBoxPassing(self,eKey)
                eKey = 
                return
        return

    def listToString(self,keyList):
        """
        This method converts a list to a string

        @param:  list of keys
        @return: string type of list of keys
        """
        # convert list to string
        keyString = ""
        for i in keyList:
            keyString += i

        return keyString
        
es = EncryptionSystem("securityb") 
