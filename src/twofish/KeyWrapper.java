package twofish;

import twofish.exceptions.InvalidKeyException;

import static twofish.Constants.*;

/**
 * Wrapper class for 64/128/192/256-bit encryption keys.
 */
public class KeyWrapper {
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
            throw new InvalidKeyException("Null key");
        int keyBytesLength = k.length;
        if (!(keyBytesLength == 8 || keyBytesLength == 16 || keyBytesLength == 24 || keyBytesLength == 32))
            throw new InvalidKeyException("Incorrect key length. Allowed key lengths: 8, 16, 24, 32 bytes.");

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
            sBoxKey[j] = IntermediateUtilityMethods.reedSolomonEncode(k32e[i], k32o[i]); // reverse order
        }
        // compute the round decryption subkeys for PHT. these same subkeys
        // will be used in encryption but will be applied in reverse order.
        int q, A, B;
        int[] subKeys = new int[subkeyCnt];
        for (i = q = 0; i < subkeyCnt / 2; i++, q += SK_STEP) {
            A = IntermediateUtilityMethods.F32(k64Cnt, q, k32e); // A uses even key entities
            B = IntermediateUtilityMethods.F32(k64Cnt, q + SK_BUMP, k32o); // B uses odd  key entities
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
                    sBox[2 * i] = MDS[0][(P[P_01][b0] & 0xFF) ^ IntermediateUtilityMethods.LSB16(k0)];
                    sBox[2 * i + 1] = MDS[1][(P[P_11][b1] & 0xFF) ^ IntermediateUtilityMethods.MB16(k0)];
                    sBox[0x200 + 2 * i] = MDS[2][(P[P_21][b2] & 0xFF) ^ IntermediateUtilityMethods.MSB16(k0)];
                    sBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][b3] & 0xFF) ^ IntermediateUtilityMethods.MSB8(k0)];
                    break;
                case 0: // same as 4
                    b0 = (P[P_04][b0] & 0xFF) ^ IntermediateUtilityMethods.LSB16(k3);
                    b1 = (P[P_14][b1] & 0xFF) ^ IntermediateUtilityMethods.MB16(k3);
                    b2 = (P[P_24][b2] & 0xFF) ^ IntermediateUtilityMethods.MSB16(k3);
                    b3 = (P[P_34][b3] & 0xFF) ^ IntermediateUtilityMethods.MSB8(k3);
                case 3:
                    b0 = (P[P_03][b0] & 0xFF) ^ IntermediateUtilityMethods.LSB16(k2);
                    b1 = (P[P_13][b1] & 0xFF) ^ IntermediateUtilityMethods.MB16(k2);
                    b2 = (P[P_23][b2] & 0xFF) ^ IntermediateUtilityMethods.MSB16(k2);
                    b3 = (P[P_33][b3] & 0xFF) ^ IntermediateUtilityMethods.MSB8(k2);
                case 2: // 128-bit keys
                    sBox[2 * i] = MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ IntermediateUtilityMethods.LSB16(k1)] & 0xFF) ^ IntermediateUtilityMethods.LSB16(k0)];
                    sBox[2 * i + 1] = MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ IntermediateUtilityMethods.MB16(k1)] & 0xFF) ^ IntermediateUtilityMethods.MB16(k0)];
                    sBox[0x200 + 2 * i] = MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ IntermediateUtilityMethods.MSB16(k1)] & 0xFF) ^ IntermediateUtilityMethods.MSB16(k0)];
                    sBox[0x200 + 2 * i + 1] = MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ IntermediateUtilityMethods.MSB8(k1)] & 0xFF) ^ IntermediateUtilityMethods.MSB8(k0)];
            }
        }

        return new Object[]{sBox, subKeys};
    }
}
