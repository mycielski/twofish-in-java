package twofish.exceptions;

/**
 * Thrown when data does not have expected padding.
 */
public class InvalidPaddingException extends IncorrectDecryptionException{
    public InvalidPaddingException(String message) {
        super(message);
        System.err.println("Supplied data is padded incorrectly, therefore removal od padding is impossible.");
        System.err.println(message);
    }
}
