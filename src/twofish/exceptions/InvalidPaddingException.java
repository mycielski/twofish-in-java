package twofish.exceptions;

public class InvalidPaddingException extends IllegalArgumentException{
    public InvalidPaddingException(String message) {
        System.err.println("Supplied data is padded incorrectly, therefore removal od padding is impossible.");
        System.err.println(message);
    }
}
