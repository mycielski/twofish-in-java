package twofish.exceptions;

public class InvalidPaddingException extends IncorrectDecryptionException{
    public InvalidPaddingException(String message) {
        super(message);
        System.err.println("Supplied data is padded incorrectly, therefore removal od padding is impossible.");
        System.err.println(message);
    }
}
