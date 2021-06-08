package twofish.exceptions;

public class IncorrectDecryptionException extends Exception {
    public IncorrectDecryptionException(String message) {
        System.err.println("Decrypted data is not valid.");
    }
}
