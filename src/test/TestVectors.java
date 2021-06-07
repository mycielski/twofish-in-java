package test;

import static org.junit.jupiter.api.Assertions.*;
import twofish.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TestVectors {

    @Test
    @DisplayName("KEYSIZE=128\n" +
            "\n" +
            "KEY=00000000000000000000000000000000\n" +
            "PT=00000000000000000000000000000000\n")
    public void testVector1() throws InvalidKeyException {
        byte[] key = new byte[16];
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = 0;
            plaintext[i] = 0;
        }
        Object keyObject = Key.makeKey(key);
        byte[] ciphertext = Encryption.blockEncrypt(plaintext,0,keyObject);
        byte[] decrypted = Decryption.blockDecrypt(ciphertext, 0, keyObject);
        assertEquals(decrypted.length, ciphertext.length);
        for (int i = 0; i < decrypted.length; i++) {
            assertEquals(decrypted[i], plaintext[i]);
        }
        for (int i = 0; i < ciphertext.length; i++) {
            assertEquals(ciphertext[i], decodeHexString("9F589F5CF6122C32B6BFEC2F2AE8C35A")[i]);
        }
    }

    @Test
    @DisplayName("KEYSIZE=192\n" +
            "\n" +
            "KEY=0123456789ABCDEFFEDCBA98765432100011223344556677" +
            "PT=00000000000000000000000000000000")
    public void testVector2() throws InvalidKeyException {
        byte[] key = decodeHexString("0123456789ABCDEFFEDCBA98765432100011223344556677");
        byte[] plaintext = decodeHexString("00000000000000000000000000000000");
        Object keyObject = Key.makeKey(key);
        byte[] ciphertext = Encryption.blockEncrypt(plaintext,0,keyObject);
        byte[] decrypted = Decryption.blockDecrypt(ciphertext,0,keyObject);
        assertEquals(decrypted.length, ciphertext.length);
        for (int i = 0; i < decrypted.length; i++) {
            assertEquals(decrypted[i], plaintext[i]);
        }
        for (int i = 0; i < ciphertext.length; i++) {
            assertEquals(ciphertext[i], decodeHexString("CFD1D2E5A9BE9CDF501F13B892BD2248")[i]);
        }

    }


    public byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }
    public byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }
    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }


}