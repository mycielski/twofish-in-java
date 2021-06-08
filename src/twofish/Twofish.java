package twofish;

import twofish.exceptions.InvalidKeyException;

import static twofish.Decryption.blockDecrypt;
import static twofish.Encryption.blockEncrypt;
import static twofish.KeyWrapper.makeKey;

public class Twofish {

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

    public static byte[] twofishECBDecrypt(byte[] ciphertextBytes, byte[] keyBytes) throws InvalidKeyException {
        byte[] plaintextBytes = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < ciphertextBytes.length; i += 16) {
            byte[] decryptedBlock = blockDecrypt(ciphertextBytes, i, key);
            plaintextBytes = IntermediateUtilityMethods.concatenateArrays(plaintextBytes, decryptedBlock);
        }
        return Padding.removePadding(plaintextBytes);
    }


}
