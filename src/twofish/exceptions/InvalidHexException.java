package twofish.exceptions;

/**
 * Thrown when a string or char getting parsed as a hex number contains a digit from outside of the hex range of {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F}
 */
public class InvalidHexException extends IllegalArgumentException {
    public InvalidHexException(String message) {
        System.err.println(message);
    }
}
