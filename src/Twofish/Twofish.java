package Twofish;// $Id: $

import Twofish.InvalidKeyException;
import static Twofish.Constants.*;

public final class Twofish // implicit no-argument constructor
{

// Basic API methods
//...........................................................................

    /**
     * Expand a user-supplied key material into a session key.
     *
     * @param k The 64/128/192/256-bit user-key to use.
     * @return This cipher's round keys.
     * @throws InvalidKeyException If the key is invalid.
     */
    public static Object makeKey(byte[] k)
            throws InvalidKeyException {
        if (k == null)
            throw new InvalidKeyException("Empty key");
        int keyBytesLength = k.length;
        if (!(keyBytesLength == 8 || keyBytesLength == 16 || keyBytesLength == 24 || keyBytesLength == 32))
            throw new InvalidKeyException("Incorrect key length");

        int k64Cnt = keyBytesLength / 8;
        int subkeyCnt = ROUND_SUBKEYS + 2 * ROUNDS;
        int[] k32e = new int[4]; // even 32-bit entities
        int[] k32o = new int[4]; // odd 32-bit entities
        int[] sBoxKey = new int[4];
        //
        // split user key material into even and odd 32-bit entities and
        // compute S-box keys using (12, 8) Reed-Solomon code over GF(256)
        //
        int i, j, offset = 0;
        for (i = 0, j = k64Cnt - 1; i < 4 && offset < keyBytesLength; i++, j--) {
            k32e[i] = (k[offset++] & 0xFF) |
                    (k[offset++] & 0xFF) << 8 |
                    (k[offset++] & 0xFF) << 16 |
                    (k[offset++] & 0xFF) << 24;
            k32o[i] = (k[offset++] & 0xFF) |
                    (k[offset++] & 0xFF) << 8 |
                    (k[offset++] & 0xFF) << 16 |
                    (k[offset++] & 0xFF) << 24;
            sBoxKey[j] = RS_MDS_Encode(k32e[i], k32o[i]); // reverse order
        }
        // compute the round decryption subkeys for PHT. these same subkeys
        // will be used in encryption but will be applied in reverse order.
        int q, A, B;
        int[] subKeys = new int[subkeyCnt];
        for (i = q = 0; i < subkeyCnt / 2; i++, q += SK_STEP) {
            A = F32(k64Cnt, q, k32e); // A uses even key entities
            B = F32(k64Cnt, q + SK_BUMP, k32o); // B uses odd  key entities
            B = B << 8 | B >>> 24;
            A += B;
            subKeys[2 * i] = A;               // combine with a PHT
            A += B;
            subKeys[2 * i + 1] = A << SK_ROTL | A >>> (32 - SK_ROTL);
        }
        //
        // fully expand the table for speed
        //
        int k0 = sBoxKey[0];
        int k1 = sBoxKey[1];
        int k2 = sBoxKey[2];
        int k3 = sBoxKey[3];
        int b0, b1, b2, b3;
        int[] sBox = new int[4 * 256];
        for (i = 0; i < 256; i++) {
            b0 = b1 = b2 = b3 = i;
            switch (k64Cnt & 3) {
                case 1:
                    sBox[2 * i] = MDS[0][(P[P_01][b0] & 0xFF) ^ b0(k0)];
                    sBox[2 * i + 1] = MDS[1][(P[P_11][b1] & 0xFF) ^ b1(k0)];
                    sBox[0x200 + 2 * i] = MDS[2][(P[P_21][b2] & 0xFF) ^ b2(k0)];
                    sBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][b3] & 0xFF) ^ b3(k0)];
                    break;
                case 0: // same as 4
                    b0 = (P[P_04][b0] & 0xFF) ^ b0(k3);
                    b1 = (P[P_14][b1] & 0xFF) ^ b1(k3);
                    b2 = (P[P_24][b2] & 0xFF) ^ b2(k3);
                    b3 = (P[P_34][b3] & 0xFF) ^ b3(k3);
                case 3:
                    b0 = (P[P_03][b0] & 0xFF) ^ b0(k2);
                    b1 = (P[P_13][b1] & 0xFF) ^ b1(k2);
                    b2 = (P[P_23][b2] & 0xFF) ^ b2(k2);
                    b3 = (P[P_33][b3] & 0xFF) ^ b3(k2);
                case 2: // 128-bit keys
                    sBox[2 * i] = MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ b0(k1)] & 0xFF) ^ b0(k0)];
                    sBox[2 * i + 1] = MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ b1(k1)] & 0xFF) ^ b1(k0)];
                    sBox[0x200 + 2 * i] = MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ b2(k1)] & 0xFF) ^ b2(k0)];
                    sBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ b3(k1)] & 0xFF) ^ b3(k0)];
            }
        }

        Object sessionKey = new Object[]{sBox, subKeys};

        return sessionKey;
    }

    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param in         The plaintext.
     * @param inOffset   Index of in from which to start considering data.
     * @param sessionKey The session key to use for encryption.
     * @return The ciphertext generated from a plaintext using the session key.
     */
    public static byte[] blockEncrypt(byte[] in, int inOffset, Object sessionKey) {
        Object[] sk = (Object[]) sessionKey; // extract S-box and session key
        int[] sBox = (int[]) sk[0];
        int[] sKey = (int[]) sk[1];


        int x0 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x1 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x2 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x3 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;

        x0 ^= sKey[INPUT_WHITEN];
        x1 ^= sKey[INPUT_WHITEN + 1];
        x2 ^= sKey[INPUT_WHITEN + 2];
        x3 ^= sKey[INPUT_WHITEN + 3];

        int t0, t1;
        int k = ROUND_SUBKEYS;
        for (int R = 0; R < ROUNDS; R += 2) {
            t0 = Fe32(sBox, x0, 0);
            t1 = Fe32(sBox, x1, 3);
            x2 ^= t0 + t1 + sKey[k++];
            x2 = x2 >>> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >>> 31;
            x3 ^= t0 + 2 * t1 + sKey[k++];

            t0 = Fe32(sBox, x2, 0);
            t1 = Fe32(sBox, x3, 3);
            x0 ^= t0 + t1 + sKey[k++];
            x0 = x0 >>> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >>> 31;
            x1 ^= t0 + 2 * t1 + sKey[k++];
        }
        x2 ^= sKey[OUTPUT_WHITEN];
        x3 ^= sKey[OUTPUT_WHITEN + 1];
        x0 ^= sKey[OUTPUT_WHITEN + 2];
        x1 ^= sKey[OUTPUT_WHITEN + 3];

        byte[] result = new byte[]{
                (byte) x2, (byte) (x2 >>> 8), (byte) (x2 >>> 16), (byte) (x2 >>> 24),
                (byte) x3, (byte) (x3 >>> 8), (byte) (x3 >>> 16), (byte) (x3 >>> 24),
                (byte) x0, (byte) (x0 >>> 8), (byte) (x0 >>> 16), (byte) (x0 >>> 24),
                (byte) x1, (byte) (x1 >>> 8), (byte) (x1 >>> 16), (byte) (x1 >>> 24),
        };

        return result;
    }

    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param in         The ciphertext.
     * @param inOffset   Index of in from which to start considering data.
     * @param sessionKey The session key to use for decryption.
     * @return The plaintext generated from a ciphertext using the session key.
     */
    public static byte[] blockDecrypt(byte[] in, int inOffset, Object sessionKey) {
        Object[] sk = (Object[]) sessionKey; // extract S-box and session key
        int[] sBox = (int[]) sk[0];
        int[] sKey = (int[]) sk[1];


        int x2 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x3 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x0 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;
        int x1 = (in[inOffset++] & 0xFF) |
                (in[inOffset++] & 0xFF) << 8 |
                (in[inOffset++] & 0xFF) << 16 |
                (in[inOffset++] & 0xFF) << 24;

        x2 ^= sKey[OUTPUT_WHITEN];
        x3 ^= sKey[OUTPUT_WHITEN + 1];
        x0 ^= sKey[OUTPUT_WHITEN + 2];
        x1 ^= sKey[OUTPUT_WHITEN + 3];

        int k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
        int t0, t1;
        for (int R = 0; R < ROUNDS; R += 2) {
            t0 = Fe32(sBox, x2, 0);
            t1 = Fe32(sBox, x3, 3);
            x1 ^= t0 + 2 * t1 + sKey[k--];
            x1 = x1 >>> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >>> 31;
            x0 ^= t0 + t1 + sKey[k--];

            t0 = Fe32(sBox, x0, 0);
            t1 = Fe32(sBox, x1, 3);
            x3 ^= t0 + 2 * t1 + sKey[k--];
            x3 = x3 >>> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >>> 31;
            x2 ^= t0 + t1 + sKey[k--];
        }
        x0 ^= sKey[INPUT_WHITEN];
        x1 ^= sKey[INPUT_WHITEN + 1];
        x2 ^= sKey[INPUT_WHITEN + 2];
        x3 ^= sKey[INPUT_WHITEN + 3];

        byte[] result = new byte[]{
                (byte) x0, (byte) (x0 >>> 8), (byte) (x0 >>> 16), (byte) (x0 >>> 24),
                (byte) x1, (byte) (x1 >>> 8), (byte) (x1 >>> 16), (byte) (x1 >>> 24),
                (byte) x2, (byte) (x2 >>> 8), (byte) (x2 >>> 16), (byte) (x2 >>> 24),
                (byte) x3, (byte) (x3 >>> 8), (byte) (x3 >>> 16), (byte) (x3 >>> 24),
        };

        return result;
    }

    /**
     * A basic symmetric encryption/decryption test.
     */
    public static boolean self_test() {
        return self_test(BLOCK_SIZE);
    }


// own methods
//...........................................................................

    private static final int b0(int x) {
        return x & 0xFF;
    }

    private static final int b1(int x) {
        return (x >>> 8) & 0xFF;
    }

    private static final int b2(int x) {
        return (x >>> 16) & 0xFF;
    }

    private static final int b3(int x) {
        return (x >>> 24) & 0xFF;
    }

    /**
     * Use (12, 8) Reed-Solomon code over GF(256) to produce a key S-box 32-bit entity from two key material 32-bit
     * entities.
     *
     * @param k0 1st 32-bit entity.
     * @param k1 2nd 32-bit entity.
     * @return Remainder polynomial generated using RS code
     */
    private static final int RS_MDS_Encode(int k0, int k1) {
        int r = k1;
        for (int i = 0; i < 4; i++) // shift 1 byte at a time
            r = RS_rem(r);
        r ^= k0;
        for (int i = 0; i < 4; i++)
            r = RS_rem(r);
        return r;
    }

    /**
     * Reed-Solomon code parameters: (12, 8) reversible code:<p>
     * <pre>
     *   g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
     * </pre>
     * where a = primitive root of field generator 0x14D
     */
    private static final int RS_rem(int x) {
        int b = (x >>> 24) & 0xFF;
        int g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
        int g3 = (b >>> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0) ^ g2;
        int result = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
        return result;
    }

    private static final int F32(int k64Cnt, int x, int[] k32) {
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

    private static final int Fe32(int[] sBox, int x, int R) {
        return sBox[2 * _b(x, R)] ^
                sBox[2 * _b(x, R + 1) + 1] ^
                sBox[0x200 + 2 * _b(x, R + 2)] ^
                sBox[0x200 + 2 * _b(x, R + 3) + 1];
    }

    private static final int _b(int x, int N) {
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

    /**
     * @return The length in bytes of the Algorithm input block.
     */
    public static int blockSize() {
        return BLOCK_SIZE;
    }

    /**
     * A basic symmetric encryption/decryption test for a given key size.
     */
    private static boolean self_test(int keysize) {
        boolean ok = false;
        try {
            byte[] keyBytes = new byte[keysize];
            byte[] plaintextBytes = new byte[BLOCK_SIZE];
            int i;

            for (i = 0; i < keysize; i++)
                keyBytes[i] = (byte) i;
            System.out.println("plaintext:");
            for (i = 0; i < BLOCK_SIZE; i++) {
                plaintextBytes[i] = (byte) i;
                System.out.println(plaintextBytes[i]);
            }

            Object key = makeKey(keyBytes);

            byte[] ciphertext = blockEncrypt(plaintextBytes, 0, key);
            System.out.println("ciphertext:");
            for (byte b : ciphertext) {
                System.out.println(b);
            }
            byte[] ciphertextDecrypted = blockDecrypt(ciphertext, 0, key);
            System.out.println("ciphertext decrypted:");
            for (byte b : ciphertextDecrypted) {
                System.out.println(b);
            }
            //ok = areEqual(plaintextBytes, ciphertextDecrypted);
            ok = plaintextBytes.equals(ciphertextDecrypted);
            if (!ok)
                throw new RuntimeException("Symmetric operation failed");
        } catch (Exception x) {
        }
        return ok;
    }


// utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................

    /**
     * @return True iff the arrays have identical contents.
     */
    private static boolean areEqual(byte[] a, byte[] b) {
        int aLength = a.length;
        if (aLength != b.length)
            return false;
        for (int i = 0; i < aLength; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }



// main(): use to generate the Intermediate Values KAT
//...........................................................................

    public static void main(String[] args) {
        System.out.println(self_test(16));
        System.out.println(self_test(24));
        System.out.println(self_test(32));
    }
}