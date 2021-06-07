package Twofish;

import static Twofish.Constants.*;

public class Decryption {
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
            t0 = IntermediateUtilityMethods.Fe32(sBox, x2, 0);
            t1 = IntermediateUtilityMethods.Fe32(sBox, x3, 3);
            x1 ^= t0 + 2 * t1 + sKey[k--];
            x1 = x1 >>> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >>> 31;
            x0 ^= t0 + t1 + sKey[k--];

            t0 = IntermediateUtilityMethods.Fe32(sBox, x0, 0);
            t1 = IntermediateUtilityMethods.Fe32(sBox, x1, 3);
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
}
