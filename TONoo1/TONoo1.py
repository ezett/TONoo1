"""
Implementation of the 1-out-of-N Oblivious Transfer scheme presented by T. Chou
and C. Orlandi: The Simplest Protocol for Oblivious Transfer, 2015.

Enhanced via elliptic curve cryptography (ECC) and the concealment of all
response indices, which therewith don't get revealed to the receiver, except the
one, which is of interest to the receiver, of course.
"""

import nacl.public, nacl.secret, nacl.utils
from nacl.bindings import crypto_scalarmult_ed25519_SCALARBYTES
from nacl.bindings import crypto_scalarmult_ed25519_base
from nacl.bindings import crypto_scalarmult_ed25519
from nacl.bindings import crypto_core_ed25519_sub
from nacl.bindings import crypto_core_ed25519_add
from hashlib import blake2b


CONCEAL_RESPONSE_INDICES = True


def calcMac(inputBytes: bytes, keyBytes: bytes = b'') -> bytes:
    """
    Calculates the keyed hash (Blake2b message authentication code) of an
    input.

    :param inputBytes: The encoded input as byte string
    :return: The Blake2b MAC of the input.
    """
    return blake2b(
        inputBytes,
        digest_size=nacl.public.PrivateKey.SIZE,
        key=keyBytes,
    ).digest()



class Receiver():
    """
    A class representing the Receiver of the 1-out-of-N Oblivious Transfer
    scheme.
    """

    def __init__(self, senderOTKey: bytes) -> None:
        """
        Initialises the Receiver with the Oblivious Transfer Key of the Sender.

        :param senderOTKey: The public Oblivious Transfer key of the Sender.
        """
        self.__senderOTKey = senderOTKey
        self.__otSecrets = {}


    def getRequestOTKey(self, entryIndex: str) -> bytes:
        """
        Given the index of an entry of interest to the Receiver, returns the
        tailored public Oblivious Transfer key of the Receiver. Further, the
        Oblivious Transfer secret key is stored internally, which later is used
        to decrypt the entry of interest to the Receiver.

        :param entryIndex: The index of an entry of interest to the Receiver. It
        must be provided as a string.
        """
        entryIndexBytes = entryIndex.encode('utf8')
        sk = nacl.utils.random(crypto_scalarmult_ed25519_SCALARBYTES)
        pk = crypto_scalarmult_ed25519_base(sk)
        self.__otSecrets[entryIndex] = crypto_scalarmult_ed25519(sk, self.__senderOTKey)
        return crypto_core_ed25519_add(
            crypto_scalarmult_ed25519(
                b'\0' * (32 - len(entryIndexBytes)) + entryIndexBytes,
                self.__senderOTKey),
            pk
        )


    def decryptResponse(self, ciphers: dict) -> str:
        """
        Returns the decrypted entry of interest to the Receiver.

        :param params: A python dict containing the following:
            'ciphers' with a list of the encrypted entries received by the Sender,
        """
        D = {}
        for entryIndex, otSecret in self.__otSecrets.items():
            origEntryIndex = entryIndex
            if CONCEAL_RESPONSE_INDICES:
                entryIndex = calcMac(entryIndex.encode('utf8'), keyBytes=otSecret)
            c = ciphers[entryIndex]
            D[origEntryIndex] = nacl.secret.SecretBox(otSecret).decrypt(c).decode()
        return D



class Sender():
    """
    A class representing the Sender of the 1-out-of-N Oblivious Transfer
    scheme.
    """

    def __init__(self) -> None:
        """
        Initialises the Sender.
        """
        self.__senderOTSecret = nacl.utils.random(
        #bytes(random.getrandbits(8) for _ in range(
            crypto_scalarmult_ed25519_SCALARBYTES
        )
        #)
        self.__senderOTKey = crypto_scalarmult_ed25519_base(
            self.__senderOTSecret
        )
        self.__senderOTU = crypto_scalarmult_ed25519(
            self.__senderOTSecret,
            self.__senderOTKey
        )


    def register(self) -> bytes:
        """
        Returns the Oblivious Transfer Key of the Sender.
        """
        return self.__senderOTKey


    def retrieve(self, params: dict) -> dict:
        """
        Returns all encrypted entries provided to the Sender via the 'params'
        argument (usually all entries of a database). It should contain the
        entry of interest to the Receiver, although the Sender is unaware of
        which entry is the one. Each entry must be a python dict containing the
        following keys:
            'index' as the index of the entry given by a string,
            'value' as the value of the entry given by a string.
        All entries will be extended with a new key, which must be calculated
        only once per Sender instance:
            'indexOTU' as a specific Oblivious Transfer index value calculated
                in dependence of the senderOTKey.

        :param params: A python dict containing the following:
            'requestOTKey' as the tailored public Oblivious Transfer key of the Receiver,
            'entries' with a list of all entries to be sent to the Receiver.
        """
        sharedOTSecret = crypto_scalarmult_ed25519(
            self.__senderOTSecret,
            params['requestOTKey']
        )
        C = {}
        for entry in params['entries']:
            entryIndexBytes = entry['index'].encode('utf8')
            try:
                tmp = entry['indexOTU']
            except:
                entry['indexOTU'] = crypto_scalarmult_ed25519(
                    b'\0' * (32 - len(entryIndexBytes)) + entryIndexBytes,
                    self.__senderOTU
                )
            K = crypto_core_ed25519_sub(
                sharedOTSecret,
                entry['indexOTU']
            )
            c = nacl.secret.SecretBox(K).encrypt(entry['value'].encode('utf8'))
            if CONCEAL_RESPONSE_INDICES:
                i = calcMac(
                    entryIndexBytes,
                    keyBytes=K,
                )
            else:
                i = entry['index']
            C[i] = c
        return C




