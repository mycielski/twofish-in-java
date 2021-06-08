package twofish;


import twofish.exceptions.InvalidHexException;
import twofish.exceptions.WrongNumberOfBitsException;

import java.util.Arrays;

import static twofish.Constants.*;

/**
 * Class containing all the methods during the rounds of encrypting and decrypting data and methods for handling hexadecimal user input.
 */
public class IntermediateUtilityMethods {

    //TODO javadoc
    protected static int b0(int x) {
        return x & 0xFF;
    }

    //TODO javadoc
    protected static int b1(int x) {
        return (x >>> 8) & 0xFF;
    }

    //TODO javadoc
    protected static int b2(int x) {
        return (x >>> 16) & 0xFF;
    }

    //TODO javadoc
    protected static int b3(int x) {
        return (x >>> 24) & 0xFF;
    }

    //TODO javadoc
    protected static int F32(int k64Cnt, int x, int[] k32) {
        int b0 = b0(x);
        int b1 = b1(x);
        int b2 = b2(x);
        int b3 = b3(x);
        int k0 = k32[0];
        int k1 = k32[1];
        int k2 = k32[2];
        int k3 = k32[3];

        int result = 0;
        switch (k64Cnt & 3) {
            case 1:
                result =
                        MDS[0][(P[P_01][b0] & 0xFF) ^ b0(k0)] ^
                                MDS[1][(P[P_11][b1] & 0xFF) ^ b1(k0)] ^
                                MDS[2][(P[P_21][b2] & 0xFF) ^ b2(k0)] ^
                                MDS[3][(P[P_31][b3] & 0xFF) ^ b3(k0)];
                break;
            case 0:  // same as 4
                b0 = (P[P_04][b0] & 0xFF) ^ b0(k3);
                b1 = (P[P_14][b1] & 0xFF) ^ b1(k3);
                b2 = (P[P_24][b2] & 0xFF) ^ b2(k3);
                b3 = (P[P_34][b3] & 0xFF) ^ b3(k3);
            case 3:
                b0 = (P[P_03][b0] & 0xFF) ^ b0(k2);
                b1 = (P[P_13][b1] & 0xFF) ^ b1(k2);
                b2 = (P[P_23][b2] & 0xFF) ^ b2(k2);
                b3 = (P[P_33][b3] & 0xFF) ^ b3(k2);
            case 2:                             // 128-bit keys (optimize for this case)
                result =
                        MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ b0(k1)] & 0xFF) ^ b0(k0)] ^
                                MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ b1(k1)] & 0xFF) ^ b1(k0)] ^
                                MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ b2(k1)] & 0xFF) ^ b2(k0)] ^
                                MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ b3(k1)] & 0xFF) ^ b3(k0)];
                break;
        }
        return result;
    }

    //TODO zrozumieć to:
    /**
     * Use (12, 8) Reed-Solomon code over GF(256) to produce a key S-box 32-bit entity from two key material 32-bit
     * entities.
     *
     * @param k0 1st 32-bit entity.
     * @param k1 2nd 32-bit entity.
     * @return Remainder polynomial generated using RS code
     */
    protected static int reedSolomonEncode(int k0, int k1) {
        int r = k1;
        for (int i = 0; i < 4; i++) // shift 1 byte at a time
            r = reedSolomonRemainder(r);
        r ^= k0;
        for (int i = 0; i < 4; i++)
            r = reedSolomonRemainder(r);
        return r;
    }

    //TODO zrozumieć to:
    /**
     * Reed-Solomon code parameters: (12, 8) reversible code:<p>
     * <pre>
     *   g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
     * </pre>
     * where a = primitive root of field generator 0x14D
     */
    private static int reedSolomonRemainder(int x) {
        int b = (x >>> 24) & 0xFF;
        int g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
        int g3 = (b >>> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0) ^ g2;
        int result = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
        return result;
    }


    //TODO javadoc
    private static int b(int x, int N) {
        int result = 0;
        switch (N % 4) {
            case 0:
                result = b0(x);
                break;
            case 1:
                result = b1(x);
                break;
            case 2:
                result = b2(x);
                break;
            case 3:
                result = b3(x);
                break;
        }
        return result;
    }


    //TODO javadoc
    protected static int Fe32(int[] sBox, int x, int R) {
        return sBox[2 * b(x, R)] ^
                sBox[2 * b(x, R + 1) + 1] ^
                sBox[0x200 + 2 * b(x, R + 2)] ^
                sBox[0x200 + 2 * b(x, R + 3) + 1];
    }

    /**
     * Method to convert a string of hex digits to a byte array.
     * @param hexString String of hex digits
     * @return byte array
     * @throws WrongNumberOfBitsException thrown when hexString cannot be converted to bytes due to its length not being
     * a multiple of 8.
     */
    static byte[] decodeHexString(String hexString) throws WrongNumberOfBitsException {
        if (hexString.length() % 2 == 1) {
            throw new WrongNumberOfBitsException(
                    "Bit length not a multiple of 8. String: " + hexString);
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    /**
     * Method to convert a hex string of two characters to a single byte
     * @param hexString Hex string of length 2
     * @return byte parsed from hexString
     */
    private static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    /**
     * Method to convert a single hex digit to int
     * @param hexChar a hexadecimal digit
     * @return value of the hexChar as an int
     */
    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new InvalidHexException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    /**
     * Method to concatenate byte arrays
     * @param array1 first byte array
     * @param array2 second byte array
     * @return 1 dimensional byte array consisting of the first array's values and then the second array values.
     */
    static byte[] concatenateArrays(byte[] array1, byte[] array2) {
        byte[] result = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
}
