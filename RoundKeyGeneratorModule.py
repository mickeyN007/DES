__author__ = "Michael Oduah\nBabatunde Adesoye"
__date__ = "10/8/2016"

class RoundKeyGenerator:
    """
    Round key Generator.
    This system is a subsystem of the DES system. The RoundKeyGenerator system
    is made up of a class "RoundKeyGenerator" and seven functions.
    Altogether, this system produces 16 keys. These keys are used to encrypt data.

    @param:  key
    @return: list of 16 keys
    """
    def __init__(self, uKey):
        """
        Class constructor
          -- This function sets the private attribute "key" to the user
             suggested key

        @param:  self, user key
        @return: void (stores key entered by user to keyPlain, initializes key to empty string, initializes a list to store generated keys)
        """
        self.__keyPlain = uKey
        self.__key = ""
        self.__keys = []

        RoundKeyGenerator.toBin(self)

    
    def toBin(self):
        """
        This method converts the private attribute key to binary

        @param:  self
        @return: void (sets private attribute key to binary)
        """
        self.__key += "".join(str(bin(ord(x))).replace("b", "") for x in self.__keyPlain)


    def parityDrop(self):
        """
        This method returns a string of 56 chars from the "key"

        * The split function uses the return value

        @param:  self
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
        newKey = RoundKeyGenerator.listToString(self,tmpList)

        return newKey

    def split(self, tmpKey):
        """
        This method splits the list of keys gotten from parity drop into two
        equal halves. 

        * The shift function uses the return values

        @param:  self, key --string
        @return: 2 keys of size 28 --tuple
        """
        # split list into 2 equal parts
        a = tmpKey[:28]
        b = tmpKey[28:]

        return (a,b)
        
    def shift(self, keyTuple, roundStep):
        """
        This method shifts the bits of the key either a bit to the left or to the
        right, depending on the key we are trying to produce

        * The compress method uses the return value

        @param:  self, left and right keys --tuple, keyNumber --int
        @return: key --string
        """
        # initializations
        newKey = ""
        
        # get values
        a = keyTuple[0]
        b = keyTuple[1]
        if roundStep == 1 or roundStep == 2 or roundStep == 9 or roundStep == 16:
            # one bit shift
            # left
            for i in range(1,28):
                newKey += a[i]
            newKey += a[0]
            # right
            for ii in range(1,28):
                newKey += b[ii]
            newKey += b[0]
        else:
            # two bit shift
            # left
            for i in range(2,28):
                newKey += a[i]
            newKey += a[0] + a[1]
            # right
            for ii in range(2,28):
                newKey += b[ii]
            newKey += b[0] + b[1]

        return newKey

    def compress(self, newKey):
        """
        This method returns a string of 48 chars from the "key"

        * The expansion function uses the return value

        @param:  self, key --string
        @return: key --string
        """
        # create list of indexes
        indexes = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, \
                   23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,  \
                   41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,\
                   44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

        keyList = list(newKey)

        tmpList = []

        for i in indexes:
            tmpList.append(keyList[i - 1])

        # convert back to string
        newKey = RoundKeyGenerator.listToString(self,tmpList)

        return newKey
    
    def expand(self, newKey):
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
        newKey = RoundKeyGenerator.listToString(self,tmpList)

        return newKey

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

    def generate(self):
        """
        This is the main method in the system.
        It calls all the necessary functions needed to generate the 16 keys

        Functions in order (Done ones):
           -- toBin
           -- parityDrop
           
        Functions in order (Done 16 times):
           -- split
           -- shift
           -- merge
           -- compress

        @param:  self
        @return: list of keys
        """
        # do a parity drop
        key = RoundKeyGenerator.parityDrop(self)
        
        # process 16 times
        for i in range(1,17):
            key = RoundKeyGenerator.split(self,key)
            key = RoundKeyGenerator.shift(self,key,i)
            key = RoundKeyGenerator.compress(self,key)

            # add key to private attribute keys
            self.__keys.append(key)

            key = RoundKeyGenerator.expand(self,key)

        return self.__keys
