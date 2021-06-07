import twofish.*;


public class Main {

    public static void main(String[] args) throws InvalidKeyException {
        byte[] key = new byte[16];
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = 0;
            plaintext[i] = 0;
        }
        Object keyObject = Key.makeKey(key);
        byte[] ciphertext = Encryption.blockEncrypt(plaintext,0,keyObject);
        for (byte b : ciphertext) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println();
        byte[] decrypted = Decryption.blockDecrypt(ciphertext, 0, keyObject);
        for (byte b : decrypted) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println();
    }
}
