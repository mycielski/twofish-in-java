package twofish.exceptions;

/**
 * Thrown upon discovery of incorrectly decrypted data.
 */
public class IncorrectDecryptionException extends Exception {
    public IncorrectDecryptionException(String message) {
        System.err.println("Decrypted data is not valid.");
    }
}
