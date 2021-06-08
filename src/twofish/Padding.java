package twofish;

import twofish.exceptions.IncorrectDecryptionException;
import twofish.exceptions.InvalidPaddingException;

import java.util.Random;

import static twofish.Constants.PADDING_BLOCK1;
import static twofish.Constants.PADDING_BLOCK2;

/**
 * Class contaning methods used to pad data before encryption and remove padding after decryption.
 */
class Padding {

    /**
     * Applies padding to data.
     * If byte-length of data is a multiple of 16, the padding is PADDNIG_BLOCK1 and PADDING_BLOCK2 added at the start of the data.
     * If byte-length of data is not a mutiple of 16, the padding is PADDING_BLOCK1 and random bytes to match the data byte-length to a multiple of 16.
     * PADDING_BLOCK1 consists of all random bytes except for its first byte which is always 10000000.
     * Similarly, PADDING_BLOCK2 is all random except for the last byte which is always 00000001.
     * If instead of PADDNIG_BLOCK2 the padding needed is shorter, then it also is random bytes except for its last, which is 00000001.
     * @param plaintextBytes data to pad
     * @return padded data
     */
    static byte[] padding(byte[] plaintextBytes) {
        if (plaintextBytes.length % 16 == 0) {
            return IntermediateUtilityMethods.concatenateArrays(PADDING_BLOCK1, IntermediateUtilityMethods.concatenateArrays(PADDING_BLOCK2, plaintextBytes));
        } else {
            int paddingLength = 16 - plaintextBytes.length % 16;
            byte[] padding = new byte[paddingLength];
            padding[paddingLength - 1] = (byte) 1;
            for (int i = 0; i < padding.length - 1; i++) {
                Random random = new Random();
                padding[i] = (byte) (random.nextInt(61) + 2);
            }
            byte[] output;
            output = IntermediateUtilityMethods.concatenateArrays(PADDING_BLOCK1, padding);
            output = IntermediateUtilityMethods.concatenateArrays(output, plaintextBytes);
            return output;
        }
    }

    /**
     * Removes padding applied by the padding() method.
     * @param paddedText padded text
     * @return text with removed padding
     */
    static byte[] removePadding(byte[] paddedText) {
        int paddingBytes = 0;
        if (paddedText[0] == (byte) 128) {
            paddingBytes++;
            while (paddedText[paddingBytes] != (byte) 1) {
                paddingBytes++;
                if (paddingBytes > 32) {
                    throw new InvalidPaddingException("Too many padding bytes for the data to be correct.");
                }
            }
            if (paddedText[paddingBytes] == (byte) 1) {
                paddingBytes++;
                byte[] plaintextWithoutPadding = new byte[paddedText.length - paddingBytes];
                for (int i = paddingBytes; i < paddedText.length; i++) {
                    plaintextWithoutPadding[i - paddingBytes] = paddedText[i];
                }
                return plaintextWithoutPadding;
            } else {
                throw new InvalidPaddingException("It appears that some padding bytes are missing.");
            }
        } else {
            throw new InvalidPaddingException("Padding appears to have already been removed.");
        }
    }

}
