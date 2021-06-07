package twofish;

import java.util.Arrays;

import static twofish.Constants.BLOCK_SIZE;
import static twofish.Constants.PADDING_BLOCK;
import static twofish.Decryption.blockDecrypt;
import static twofish.Encryption.blockEncrypt;
import static twofish.KeyWrapper.makeKey;

public class Twofish {

    private static boolean isPaddingBlock(byte[] block) {
        return Arrays.equals(block, PADDING_BLOCK);
    }

    private static byte[] decodeHexString(String hexString) throws InvalidKeyException {
        if (hexString.length() % 2 == 1) {
            throw new InvalidKeyException(
                    "Non-integer number of bytes.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    private static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    public static byte[] encryptByteArray(byte[] plaintext, String keyString) throws InvalidKeyException {
        byte[] keyBytes = decodeHexString(keyString);
        return encryptByteArray(plaintext, keyBytes);
    }

    public static byte[] decryptByteArray(byte[] ciphertext, String keyString) throws InvalidKeyException {
        byte[] keyBytes = decodeHexString(keyString);
        return decryptByteArray(ciphertext, keyBytes);
    }

    public static byte[] encryptByteArray(byte[] plaintext, byte[] keyBytes) throws InvalidKeyException {
        byte[] plaintextBytes = padding(plaintext);
        byte[] ciphertext = new byte[0];

        Object key = makeKey(keyBytes);

        for (int i = 0; i < plaintextBytes.length; i += 16) {
            byte[] encryptedBlock = blockEncrypt(plaintextBytes, i, key);
            ciphertext = concatenateArrays(ciphertext, encryptedBlock);
        }
        return ciphertext;
    }

    public static byte[] decryptByteArray(byte[] ciphertextBytes, byte[] keyBytes) throws InvalidKeyException {
        byte[] plaintextBytes = new byte[0];

        Object key = makeKey(keyBytes);

        boolean ciphertextIsPadded = false;
        for (int i = 0; i < ciphertextBytes.length; i += 16) {
            byte[] decryptedBlock = blockDecrypt(ciphertextBytes, i, key);
            if (i == 0 && isPaddingBlock(decryptedBlock)) {
                ciphertextIsPadded = true;
                continue;
            } else if (i == 16 && ciphertextIsPadded) {
                int paddingBytes = 0;
                for (byte b :
                        decryptedBlock) {
                    if (b == (byte) 0) {
                        paddingBytes++;
                    } else if (b == (byte) 1) {
                        paddingBytes++;
                        break;
                    }
                }
                System.out.println(paddingBytes);
                byte[] decryptedBlockWithoutPadding = new byte[BLOCK_SIZE - paddingBytes];
                for (int j = paddingBytes; j < BLOCK_SIZE; j++) {
                    decryptedBlockWithoutPadding[j - paddingBytes] = decryptedBlock[j];
                }
                plaintextBytes = concatenateArrays(plaintextBytes, decryptedBlockWithoutPadding);
                continue;
            }
            plaintextBytes = concatenateArrays(plaintextBytes, decryptedBlock);
        }

        return plaintextBytes;
    }

    private static byte[] padding(byte[] plaintextBytes) {
        if (plaintextBytes.length % 16 == 0) return plaintextBytes;
        else {
            int paddingLength = 16 - plaintextBytes.length % 16;
            byte[] padding = new byte[paddingLength];
            padding[paddingLength - 1] = (byte) 1;
            byte[] output;
            output = concatenateArrays(PADDING_BLOCK, padding);
            output = concatenateArrays(output, plaintextBytes);
            return output;
        }
    }

    private static byte[] concatenateArrays(byte[] array1, byte[] array2) {
        byte[] result = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

}
