package twofish;

import java.util.Random;

import static twofish.Constants.PADDING_BLOCK1;
import static twofish.Constants.PADDING_BLOCK2;

class Padding {

    static byte[] removePadding(byte[] paddedText) {
        int paddingBytes = 0;
        if (paddedText[0] == (byte) 128) {
            paddingBytes++;
            while (paddedText[paddingBytes] != (byte) 1) {
                paddingBytes++;
                if (paddingBytes > 32) {
                    //todo exception
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
                //todo exception
            }
        } else {
            //todo exception
        }
        return null;
    }

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
}
