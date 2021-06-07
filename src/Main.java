import Twofish.InvalidKeyException;

import static Twofish.Decryption.blockDecrypt;
import static Twofish.Encryption.blockEncrypt;
import static Twofish.Key.makeKey;

public class Main {

    public static void main(String[] args) throws InvalidKeyException {
	// write your code here
        byte[] keyBytes = new byte[16];
        byte[] plaintextBytes = new byte[16];

        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) i;
            plaintextBytes[i] = (byte) i;
        }

        Object key = makeKey(keyBytes);
        System.out.println(plaintextBytes);
        byte[] ciphertext = blockEncrypt(plaintextBytes,0,key);
        System.out.println(ciphertext);
        byte[] ciphertextDecrypted = blockDecrypt(ciphertext,0,key);
        System.out.println(ciphertextDecrypted);
        System.out.println(ciphertext.equals(ciphertextDecrypted));
        for (int i = 0; i < ciphertext.length; i++) {
            System.out.println(ciphertext[i] + " " + ciphertextDecrypted[i]);
        }
    }
}
