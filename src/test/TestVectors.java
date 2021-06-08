package test;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Assertions;
import twofish.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import twofish.exceptions.InvalidHexException;
import twofish.exceptions.InvalidKeyException;
import twofish.exceptions.WrongNumberOfBitsException;

class TestVectors {

    @Test
    @DisplayName("KEYSIZE=128\n" +
            "\n" +
            "KEY=00000000000000000000000000000000\n" +
            "PT=00000000000000000000000000000000\n")
    public void testVector1() throws Exception {
        String key = "00000000000000000000000000000000";
        String plaintext = "00000000000000000000000000000000";
        byte[] ciphertext = Twofish.twofishECBEncrypt(plaintext, key);
        assertArrayEquals(removePaddingFromCiphertext(ciphertext), hexStringToByteArray("9F589F5CF6122C32B6BFEC2F2AE8C35A"));
        assertArrayEquals(Twofish.twofishECBDecrypt(ciphertext, key), hexStringToByteArray(plaintext));
    }

    @Test
    @DisplayName("Wrong key length")
    public void wrongKeyLength() {
        String key = "000000000000000000000000000000000";
        String plaintext = "00000000000000000000000000000000";
        Assertions.assertThrows(WrongNumberOfBitsException.class, () -> {
            byte[] ciphertext = Twofish.twofishECBEncrypt(plaintext, key);
        });
    }

    @Test
    @DisplayName("Non-hex chars")
    public void nonHexCharacters() {
        String key = "00000000ZZ000000000000000000000000";
        String plaintext = "00000000000000000000000000000000";
        Assertions.assertThrows(InvalidHexException.class, () -> {
            byte[] ciphertext = Twofish.twofishECBEncrypt(plaintext, key);
        });
    }

    @Test
    @DisplayName("Key String is of length 0")
    public void zeroLenghtKey() {
        String key = "";
        String plaintext = "00000000000000000000000000000000";
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            byte[] ciphertext = Twofish.twofishECBEncrypt(plaintext, key);
        });
    }



    private byte[] removePaddingFromCiphertext(byte[] paddedCiphertext) {
        byte[] ciphertextWithoutPadding = new byte[16];
        for (int i = 0; i < 16; i++) {
            ciphertextWithoutPadding[i] = paddedCiphertext[paddedCiphertext.length - 16 + i];
        }
        return ciphertextWithoutPadding;
    }
    private byte[] hexStringToByteArray(String hexString) {
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
    private byte hexToByte(String hexString) {
        int firstDigit = hexCharToInt(hexString.charAt(0));
        int secondDigit = hexCharToInt(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }
    private int hexCharToInt(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }


}