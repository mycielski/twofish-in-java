package twofish;

import twofish.exceptions.InputSizeMismatchException;
import twofish.exceptions.InvalidKeyException;
import twofish.exceptions.InvalidPaddingException;

import static twofish.Decryption.blockDecrypt;
import static twofish.Encryption.blockEncrypt;
import static twofish.KeyWrapper.makeKey;

/**
 * Class contains client-facing API to encrypt and decrypt data.
 */
public class Twofish {

    /**
     * Method used to encrypt byte arrays of data with a key, also given as a byte array. Plaintext bit-length must be a
     * multiple of 8. Key must be 64/128/192/256 bits in length. WARNING! Encrypted data is padded! See twofish.Padding
     * class for more info.
     *
     * @param plaintext plaintext to encrypt
     * @param keyBytes  encryption key
     * @return ciphertext
     * @throws InvalidKeyException
     */
    public static byte[] twofishECBEncrypt(byte[] plaintext, byte[] keyBytes) throws InvalidKeyException {
        byte[] plaintextBytes = Padding.padding(plaintext);
        byte[] ciphertext = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < plaintextBytes.length; i += 16) {
            byte[] encryptedBlock = blockEncrypt(plaintextBytes, i, key);
            ciphertext = IntermediateUtilityMethods.concatenateArrays(ciphertext, encryptedBlock);
        }
        return ciphertext;
    }

    /**
     * Method used to encrypt byte arrays of data with a key, also given as a byte array. Plaintext bit-length must be a
     * multiple of 8. Key must be 64/128/192/256 bits in length. WARNING! The supplied data won't be padded. Supplied
     * data byte-length must be a multiple of 16 in order to divide data into Twofish blocks.
     *
     * @param plaintext plaintext to encrypt
     * @param keyBytes  encryption key
     * @return ciphertext
     * @throws InvalidKeyException thrown when supplied key does not conform to the Twofish key requirements
     */
    public static byte[] twofishECBEncryptNoPadding(byte[] plaintext, byte[] keyBytes) throws InvalidKeyException {
        if (plaintext.length % 16 != 0) throw new InputSizeMismatchException("Plaintext size = " + plaintext.length);

        byte[] ciphertext = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < plaintext.length; i += 16) {
            byte[] encryptedBlock = blockEncrypt(plaintext, i, key);
            ciphertext = IntermediateUtilityMethods.concatenateArrays(ciphertext, encryptedBlock);
        }
        return ciphertext;
    }

    /**
     * Method used to decrypt byte arrays of data with a key, also given as a byte array. Method decrypts padded data
     * and as such it won't decrypt data encrypted without padding. For additional info about the padding scheme refer
     * to twofish.Padding class. Plaintext bit-length must be a multiple of 8. Key must be 64/128/192/256 bits in
     * length.
     *
     * @param ciphertextBytes ciphertext to decrypt
     * @param keyBytes        decryption key
     * @return plaintext
     * @throws InvalidKeyException     thrown when supplied key does not conform to the Twofish key requirements
     * @throws InvalidPaddingException thrown when supplied plaintext was not padded correctly
     */
    public static byte[] twofishECBDecrypt(byte[] ciphertextBytes, byte[] keyBytes) throws InvalidKeyException, InvalidPaddingException {
        if (ciphertextBytes.length % 16 != 0) throw new InputSizeMismatchException("Plaintext size = " + ciphertextBytes.length);


        byte[] plaintextBytes = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < ciphertextBytes.length; i += 16) {
            byte[] decryptedBlock = blockDecrypt(ciphertextBytes, i, key);
            plaintextBytes = IntermediateUtilityMethods.concatenateArrays(plaintextBytes, decryptedBlock);
        }
        return Padding.removePadding(plaintextBytes);
    }

    public static byte[] twofishECBEncryptNoPadding(byte[] ciphertextBytes, String key) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBEncryptNoPadding(ciphertextBytes, IntermediateUtilityMethods.decodeHexString(key));
    }

    public static byte[] twofishECBEncryptNoPadding(String ciphertext, byte[] keyBytes) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBEncryptNoPadding(IntermediateUtilityMethods.decodeHexString(ciphertext), keyBytes);
    }

    public static byte[] twofishECBEncryptNoPadding(String ciphertext, String key) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBEncryptNoPadding(IntermediateUtilityMethods.decodeHexString(ciphertext), IntermediateUtilityMethods.decodeHexString(key));
    }


    /**
     * Method used to decrypt byte arrays of data with a key, also given as a byte array. Supplied ciphertext's
     * byte-length must be a multiple of 16 so that it can be divided into Twofish blocks. Key must be 64/128/192/256
     * bits in length.
     *
     * @param ciphertextBytes ciphertext to decrypt
     * @param keyBytes        decryption key
     * @return plaintext
     * @throws InvalidKeyException     thrown when supplied key does not conform to the Twofish key requirements
     * @throws InvalidPaddingException thrown when supplied plaintext was not padded correctly
     */
    public static byte[] twofishECBDecryptNoPadding(byte[] ciphertextBytes, byte[] keyBytes) throws InvalidKeyException, InvalidPaddingException {
        byte[] plaintextBytes = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < ciphertextBytes.length; i += 16) {
            byte[] decryptedBlock = blockDecrypt(ciphertextBytes, i, key);
            plaintextBytes = IntermediateUtilityMethods.concatenateArrays(plaintextBytes, decryptedBlock);
        }
        return plaintextBytes;
    }

    public static byte[] twofishECBDecryptNoPadding(byte[] ciphertextBytes, String key) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBDecryptNoPadding(ciphertextBytes, IntermediateUtilityMethods.decodeHexString(key));
    }

    public static byte[] twofishECBDecryptNoPadding(String ciphertext, byte[] keyBytes) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBDecryptNoPadding(IntermediateUtilityMethods.decodeHexString(ciphertext), keyBytes);
    }

    public static byte[] twofishECBDecryptNoPadding(String ciphertext, String key) throws InvalidKeyException, InvalidPaddingException {
        return twofishECBDecryptNoPadding(IntermediateUtilityMethods.decodeHexString(ciphertext), IntermediateUtilityMethods.decodeHexString(key));
    }

    public static byte[] twofishECBEncrypt(String plaintext, byte[] keyBytes) throws Exception {
        return twofishECBEncrypt(IntermediateUtilityMethods.decodeHexString(plaintext), keyBytes);
    }

    public static byte[] twofishECBDecrypt(String ciphertext, byte[] keyBytes) throws Exception {
        return twofishECBDecrypt(IntermediateUtilityMethods.decodeHexString(ciphertext), keyBytes);
    }

    public static byte[] twofishECBEncrypt(String plaintext, String keyString) throws Exception {
        byte[] keyBytes = IntermediateUtilityMethods.decodeHexString(keyString);
        byte[] plaintextBytes = IntermediateUtilityMethods.decodeHexString(plaintext);
        return twofishECBEncrypt(plaintextBytes, keyBytes);
    }

    public static byte[] twofishECBDecrypt(String ciphertext, String keyString) throws Exception {
        byte[] keyBytes = IntermediateUtilityMethods.decodeHexString(keyString);
        byte[] ciphertextBytes = IntermediateUtilityMethods.decodeHexString(ciphertext);
        return twofishECBDecrypt(ciphertextBytes, keyBytes);
    }

    public static byte[] twofishECBEncrypt(byte[] plaintext, String keyString) throws Exception {
        byte[] keyBytes = IntermediateUtilityMethods.decodeHexString(keyString);
        return twofishECBEncrypt(plaintext, keyBytes);
    }

    public static byte[] twofishECBDecrypt(byte[] ciphertext, String keyString) throws Exception {
        byte[] keyBytes = IntermediateUtilityMethods.decodeHexString(keyString);
        return twofishECBDecrypt(ciphertext, keyBytes);
    }

}
