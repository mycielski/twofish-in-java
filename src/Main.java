import twofish.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static twofish.Twofish.decryptByteArray;
import static twofish.Twofish.encryptByteArray;


public class Main {

    public static void main(String[] args) throws InvalidKeyException {
        try {
            String encryptionKey192bit = "D1079B789F666649B6BD7D1629F1F77E7AFF7A70CA2FF28A";

            byte[] fileCiphertext = encryptByteArray(
                    Files.readAllBytes(Paths.get("examples/plaintext.txt")),
                    encryptionKey192bit);
            File encryptedFile = new File("examples/ciphertext.txt");
            Files.write(encryptedFile.toPath(), fileCiphertext);

            byte[] filePlaintext = decryptByteArray(
                    Files.readAllBytes(Paths.get("examples/ciphertext.txt")),
                    encryptionKey192bit);
            File decryptedFile = new File("examples/decrypted.txt");
            Files.write(decryptedFile.toPath(), filePlaintext);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
