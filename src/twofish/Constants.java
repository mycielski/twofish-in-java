package twofish;

import java.util.Random;

/**
 * This class calculates and contains all constants used in encrypting and decrypting data, including padding blocks.
 */
final class Constants {

    protected static final int ROUNDS = 16; // how many rounds of encryption (default = 16)
    protected static final int BLOCK_SIZE = 16; // how many bytes in one data-block
    protected static final int ROUND_SUBKEYS = 4 + BLOCK_SIZE / 4; //number of subkeys used to whiten plain text
    protected static final int SK_STEP = 0x02020202; //a fixed constant used to generate even subkeys
    protected static final int SK_BUMP = 0x01010101; //a fixed constant used to generate odd subkeys
    protected static final int SK_ROTL = 9; //fixed number determining bit shift in keys generator

    /**
     * Fixed 8x8 permutation substitution box
     */
    protected static final byte[][] P = new byte[][]{
            {  // p0
                    (byte) 0xA9, (byte) 0x67, (byte) 0xB3, (byte) 0xE8,
                    (byte) 0x04, (byte) 0xFD, (byte) 0xA3, (byte) 0x76,
                    (byte) 0x9A, (byte) 0x92, (byte) 0x80, (byte) 0x78,
                    (byte) 0xE4, (byte) 0xDD, (byte) 0xD1, (byte) 0x38,
                    (byte) 0x0D, (byte) 0xC6, (byte) 0x35, (byte) 0x98,
                    (byte) 0x18, (byte) 0xF7, (byte) 0xEC, (byte) 0x6C,
                    (byte) 0x43, (byte) 0x75, (byte) 0x37, (byte) 0x26,
                    (byte) 0xFA, (byte) 0x13, (byte) 0x94, (byte) 0x48,
                    (byte) 0xF2, (byte) 0xD0, (byte) 0x8B, (byte) 0x30,
                    (byte) 0x84, (byte) 0x54, (byte) 0xDF, (byte) 0x23,
                    (byte) 0x19, (byte) 0x5B, (byte) 0x3D, (byte) 0x59,
                    (byte) 0xF3, (byte) 0xAE, (byte) 0xA2, (byte) 0x82,
                    (byte) 0x63, (byte) 0x01, (byte) 0x83, (byte) 0x2E,
                    (byte) 0xD9, (byte) 0x51, (byte) 0x9B, (byte) 0x7C,
                    (byte) 0xA6, (byte) 0xEB, (byte) 0xA5, (byte) 0xBE,
                    (byte) 0x16, (byte) 0x0C, (byte) 0xE3, (byte) 0x61,
                    (byte) 0xC0, (byte) 0x8C, (byte) 0x3A, (byte) 0xF5,
                    (byte) 0x73, (byte) 0x2C, (byte) 0x25, (byte) 0x0B,
                    (byte) 0xBB, (byte) 0x4E, (byte) 0x89, (byte) 0x6B,
                    (byte) 0x53, (byte) 0x6A, (byte) 0xB4, (byte) 0xF1,
                    (byte) 0xE1, (byte) 0xE6, (byte) 0xBD, (byte) 0x45,
                    (byte) 0xE2, (byte) 0xF4, (byte) 0xB6, (byte) 0x66,
                    (byte) 0xCC, (byte) 0x95, (byte) 0x03, (byte) 0x56,
                    (byte) 0xD4, (byte) 0x1C, (byte) 0x1E, (byte) 0xD7,
                    (byte) 0xFB, (byte) 0xC3, (byte) 0x8E, (byte) 0xB5,
                    (byte) 0xE9, (byte) 0xCF, (byte) 0xBF, (byte) 0xBA,
                    (byte) 0xEA, (byte) 0x77, (byte) 0x39, (byte) 0xAF,
                    (byte) 0x33, (byte) 0xC9, (byte) 0x62, (byte) 0x71,
                    (byte) 0x81, (byte) 0x79, (byte) 0x09, (byte) 0xAD,
                    (byte) 0x24, (byte) 0xCD, (byte) 0xF9, (byte) 0xD8,
                    (byte) 0xE5, (byte) 0xC5, (byte) 0xB9, (byte) 0x4D,
                    (byte) 0x44, (byte) 0x08, (byte) 0x86, (byte) 0xE7,
                    (byte) 0xA1, (byte) 0x1D, (byte) 0xAA, (byte) 0xED,
                    (byte) 0x06, (byte) 0x70, (byte) 0xB2, (byte) 0xD2,
                    (byte) 0x41, (byte) 0x7B, (byte) 0xA0, (byte) 0x11,
                    (byte) 0x31, (byte) 0xC2, (byte) 0x27, (byte) 0x90,
                    (byte) 0x20, (byte) 0xF6, (byte) 0x60, (byte) 0xFF,
                    (byte) 0x96, (byte) 0x5C, (byte) 0xB1, (byte) 0xAB,
                    (byte) 0x9E, (byte) 0x9C, (byte) 0x52, (byte) 0x1B,
                    (byte) 0x5F, (byte) 0x93, (byte) 0x0A, (byte) 0xEF,
                    (byte) 0x91, (byte) 0x85, (byte) 0x49, (byte) 0xEE,
                    (byte) 0x2D, (byte) 0x4F, (byte) 0x8F, (byte) 0x3B,
                    (byte) 0x47, (byte) 0x87, (byte) 0x6D, (byte) 0x46,
                    (byte) 0xD6, (byte) 0x3E, (byte) 0x69, (byte) 0x64,
                    (byte) 0x2A, (byte) 0xCE, (byte) 0xCB, (byte) 0x2F,
                    (byte) 0xFC, (byte) 0x97, (byte) 0x05, (byte) 0x7A,
                    (byte) 0xAC, (byte) 0x7F, (byte) 0xD5, (byte) 0x1A,
                    (byte) 0x4B, (byte) 0x0E, (byte) 0xA7, (byte) 0x5A,
                    (byte) 0x28, (byte) 0x14, (byte) 0x3F, (byte) 0x29,
                    (byte) 0x88, (byte) 0x3C, (byte) 0x4C, (byte) 0x02,
                    (byte) 0xB8, (byte) 0xDA, (byte) 0xB0, (byte) 0x17,
                    (byte) 0x55, (byte) 0x1F, (byte) 0x8A, (byte) 0x7D,
                    (byte) 0x57, (byte) 0xC7, (byte) 0x8D, (byte) 0x74,
                    (byte) 0xB7, (byte) 0xC4, (byte) 0x9F, (byte) 0x72,
                    (byte) 0x7E, (byte) 0x15, (byte) 0x22, (byte) 0x12,
                    (byte) 0x58, (byte) 0x07, (byte) 0x99, (byte) 0x34,
                    (byte) 0x6E, (byte) 0x50, (byte) 0xDE, (byte) 0x68,
                    (byte) 0x65, (byte) 0xBC, (byte) 0xDB, (byte) 0xF8,
                    (byte) 0xC8, (byte) 0xA8, (byte) 0x2B, (byte) 0x40,
                    (byte) 0xDC, (byte) 0xFE, (byte) 0x32, (byte) 0xA4,
                    (byte) 0xCA, (byte) 0x10, (byte) 0x21, (byte) 0xF0,
                    (byte) 0xD3, (byte) 0x5D, (byte) 0x0F, (byte) 0x00,
                    (byte) 0x6F, (byte) 0x9D, (byte) 0x36, (byte) 0x42,
                    (byte) 0x4A, (byte) 0x5E, (byte) 0xC1, (byte) 0xE0
            },
            {  // p1
                    (byte) 0x75, (byte) 0xF3, (byte) 0xC6, (byte) 0xF4,
                    (byte) 0xDB, (byte) 0x7B, (byte) 0xFB, (byte) 0xC8,
                    (byte) 0x4A, (byte) 0xD3, (byte) 0xE6, (byte) 0x6B,
                    (byte) 0x45, (byte) 0x7D, (byte) 0xE8, (byte) 0x4B,
                    (byte) 0xD6, (byte) 0x32, (byte) 0xD8, (byte) 0xFD,
                    (byte) 0x37, (byte) 0x71, (byte) 0xF1, (byte) 0xE1,
                    (byte) 0x30, (byte) 0x0F, (byte) 0xF8, (byte) 0x1B,
                    (byte) 0x87, (byte) 0xFA, (byte) 0x06, (byte) 0x3F,
                    (byte) 0x5E, (byte) 0xBA, (byte) 0xAE, (byte) 0x5B,
                    (byte) 0x8A, (byte) 0x00, (byte) 0xBC, (byte) 0x9D,
                    (byte) 0x6D, (byte) 0xC1, (byte) 0xB1, (byte) 0x0E,
                    (byte) 0x80, (byte) 0x5D, (byte) 0xD2, (byte) 0xD5,
                    (byte) 0xA0, (byte) 0x84, (byte) 0x07, (byte) 0x14,
                    (byte) 0xB5, (byte) 0x90, (byte) 0x2C, (byte) 0xA3,
                    (byte) 0xB2, (byte) 0x73, (byte) 0x4C, (byte) 0x54,
                    (byte) 0x92, (byte) 0x74, (byte) 0x36, (byte) 0x51,
                    (byte) 0x38, (byte) 0xB0, (byte) 0xBD, (byte) 0x5A,
                    (byte) 0xFC, (byte) 0x60, (byte) 0x62, (byte) 0x96,
                    (byte) 0x6C, (byte) 0x42, (byte) 0xF7, (byte) 0x10,
                    (byte) 0x7C, (byte) 0x28, (byte) 0x27, (byte) 0x8C,
                    (byte) 0x13, (byte) 0x95, (byte) 0x9C, (byte) 0xC7,
                    (byte) 0x24, (byte) 0x46, (byte) 0x3B, (byte) 0x70,
                    (byte) 0xCA, (byte) 0xE3, (byte) 0x85, (byte) 0xCB,
                    (byte) 0x11, (byte) 0xD0, (byte) 0x93, (byte) 0xB8,
                    (byte) 0xA6, (byte) 0x83, (byte) 0x20, (byte) 0xFF,
                    (byte) 0x9F, (byte) 0x77, (byte) 0xC3, (byte) 0xCC,
                    (byte) 0x03, (byte) 0x6F, (byte) 0x08, (byte) 0xBF,
                    (byte) 0x40, (byte) 0xE7, (byte) 0x2B, (byte) 0xE2,
                    (byte) 0x79, (byte) 0x0C, (byte) 0xAA, (byte) 0x82,
                    (byte) 0x41, (byte) 0x3A, (byte) 0xEA, (byte) 0xB9,
                    (byte) 0xE4, (byte) 0x9A, (byte) 0xA4, (byte) 0x97,
                    (byte) 0x7E, (byte) 0xDA, (byte) 0x7A, (byte) 0x17,
                    (byte) 0x66, (byte) 0x94, (byte) 0xA1, (byte) 0x1D,
                    (byte) 0x3D, (byte) 0xF0, (byte) 0xDE, (byte) 0xB3,
                    (byte) 0x0B, (byte) 0x72, (byte) 0xA7, (byte) 0x1C,
                    (byte) 0xEF, (byte) 0xD1, (byte) 0x53, (byte) 0x3E,
                    (byte) 0x8F, (byte) 0x33, (byte) 0x26, (byte) 0x5F,
                    (byte) 0xEC, (byte) 0x76, (byte) 0x2A, (byte) 0x49,
                    (byte) 0x81, (byte) 0x88, (byte) 0xEE, (byte) 0x21,
                    (byte) 0xC4, (byte) 0x1A, (byte) 0xEB, (byte) 0xD9,
                    (byte) 0xC5, (byte) 0x39, (byte) 0x99, (byte) 0xCD,
                    (byte) 0xAD, (byte) 0x31, (byte) 0x8B, (byte) 0x01,
                    (byte) 0x18, (byte) 0x23, (byte) 0xDD, (byte) 0x1F,
                    (byte) 0x4E, (byte) 0x2D, (byte) 0xF9, (byte) 0x48,
                    (byte) 0x4F, (byte) 0xF2, (byte) 0x65, (byte) 0x8E,
                    (byte) 0x78, (byte) 0x5C, (byte) 0x58, (byte) 0x19,
                    (byte) 0x8D, (byte) 0xE5, (byte) 0x98, (byte) 0x57,
                    (byte) 0x67, (byte) 0x7F, (byte) 0x05, (byte) 0x64,
                    (byte) 0xAF, (byte) 0x63, (byte) 0xB6, (byte) 0xFE,
                    (byte) 0xF5, (byte) 0xB7, (byte) 0x3C, (byte) 0xA5,
                    (byte) 0xCE, (byte) 0xE9, (byte) 0x68, (byte) 0x44,
                    (byte) 0xE0, (byte) 0x4D, (byte) 0x43, (byte) 0x69,
                    (byte) 0x29, (byte) 0x2E, (byte) 0xAC, (byte) 0x15,
                    (byte) 0x59, (byte) 0xA8, (byte) 0x0A, (byte) 0x9E,
                    (byte) 0x6E, (byte) 0x47, (byte) 0xDF, (byte) 0x34,
                    (byte) 0x35, (byte) 0x6A, (byte) 0xCF, (byte) 0xDC,
                    (byte) 0x22, (byte) 0xC9, (byte) 0xC0, (byte) 0x9B,
                    (byte) 0x89, (byte) 0xD4, (byte) 0xED, (byte) 0xAB,
                    (byte) 0x12, (byte) 0xA2, (byte) 0x0D, (byte) 0x52,
                    (byte) 0xBB, (byte) 0x02, (byte) 0x2F, (byte) 0xA9,
                    (byte) 0xD7, (byte) 0x61, (byte) 0x1E, (byte) 0xB4,
                    (byte) 0x50, (byte) 0x04, (byte) 0xF6, (byte) 0xC2,
                    (byte) 0x16, (byte) 0x25, (byte) 0x86, (byte) 0x56,
                    (byte) 0x55, (byte) 0x09, (byte) 0xBE, (byte) 0x91
            }
    };
    /**
     * Define the fixed p0/p1 permutations used in keyed S-box lookup.
     * By changing the following constant definitions, the S-boxes will automatically get changed in the Twofish engine.
     */
    protected static final int P_00 = 1;
    protected static final int P_01 = 0;
    protected static final int P_02 = 0;
    protected static final int P_03 = P_01 ^ 1;
    protected static final int P_04 = 1;
    protected static final int P_10 = 0;
    protected static final int P_11 = 0;
    protected static final int P_12 = 1;
    protected static final int P_13 = P_11 ^ 1;
    protected static final int P_14 = 0;
    protected static final int P_20 = 1;
    protected static final int P_21 = 1;
    protected static final int P_22 = 0;
    protected static final int P_23 = P_21 ^ 1;
    protected static final int P_24 = 0;
    protected static final int P_30 = 0;
    protected static final int P_31 = 1;
    protected static final int P_32 = 1;
    protected static final int P_33 = P_31 ^ 1;
    protected static final int P_34 = 1;

    /**
     * Primitive polynomial for GF(256)
     */
    protected static final int GF256_FDBK_2 = 0x169 / 2;
    protected static final int GF256_FDBK_4 = 0x169 / 4;

    /**
     * Maximum Distance Separable matrix
     */
    protected static final int[][] MDS = new int[4][256]; // blank final
    protected static final int RS_GF_FDBK = 0x14D; // field generator

    /**
     * Precompute the MDS matrix
     */
    static {
        int[] m1 = new int[2];
        int[] mX = new int[2];
        int[] mY = new int[2];
        int i, j;
        for (i = 0; i < 256; i++) {
            j = P[0][i] & 0xFF; // compute all the matrix elements
            m1[0] = j;
            mX[0] = Mx_X(j) & 0xFF;
            mY[0] = Mx_Y(j) & 0xFF;

            j = P[1][i] & 0xFF;
            m1[1] = j;
            mX[1] = Mx_X(j) & 0xFF;
            mY[1] = Mx_Y(j) & 0xFF;

            MDS[0][i] = m1[P_00] | // fill matrix with computed elements
                    mX[P_00] << 8 |
                    mY[P_00] << 16 |
                    mY[P_00] << 24;
            MDS[1][i] = mY[P_10] |
                    mY[P_10] << 8 |
                    mX[P_10] << 16 |
                    m1[P_10] << 24;
            MDS[2][i] = mX[P_20] |
                    mY[P_20] << 8 |
                    m1[P_20] << 16 |
                    mY[P_20] << 24;
            MDS[3][i] = mX[P_30] |
                    m1[P_30] << 8 |
                    mY[P_30] << 16 |
                    mX[P_30] << 24;
        }


    } // Static code - to initialize the MDS matrix

    /**
     * Linear feedback shift register
     * @param x input bit which is a linear function of its previous state
     * @return output stream from shift register used in pseudo-random generators
     */
    private static int LFSR1(int x) {
        return (x >> 1) ^
                ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
    }

    /**
     * Linear feedback shift register
     * @param x input bit which is a linear function of its previous state
     * @return output stream from shift register used in pseudo-random generators
     */
    private static int LFSR2(int x) {
        return (x >> 2) ^
                ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^
                ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
    }

    /**
     * x XOR with linear feedback shift register
     * @param x input for XOR operation
     * @return x XORed with linear feedback shift register
     */
    private static int Mx_X(int x) {
        return x ^ LFSR2(x);
    }

    /**
     * x XOR with linear feedback shift register
     * @param x input for double XOR operation
     * @return x XORed with two linear feedback shift registers
     */
    private static int Mx_Y(int x) {
        return x ^ LFSR1(x) ^ LFSR2(x);
    }



    /**
     * Padding blocks. Static code below used to initialize those padding blocks with random data to make known-plaintext attacks difficult.
     */
    protected static final byte[] PADDING_BLOCK1 = new byte[16];
    protected static final byte[] PADDING_BLOCK2 = new byte[16];

    static {
        Random random = new Random();
        PADDING_BLOCK1[0] = (byte) 128;
        for (int i = 1; i < PADDING_BLOCK1.length; i++) {
            PADDING_BLOCK1[i] = (byte) (random.nextInt(61) + 2);
        }
        PADDING_BLOCK2[15] = (byte) 1;
        for (int i = 0; i < PADDING_BLOCK2.length - 1; i++) {
            PADDING_BLOCK2[i] = (byte) (random.nextInt(61) + 2);
        }
    }
}
