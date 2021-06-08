package twofish.exceptions;

public class InvalidHexException extends IllegalArgumentException {
    public InvalidHexException(String message) {
        System.err.println(message);
    }
}
