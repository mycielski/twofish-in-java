package twofish.exceptions;

/**
 * Thrown when something cannot be parsed as bytes because its number of bits is not a multiple of 8.
 */
public class WrongNumberOfBitsException extends IllegalArgumentException{
    public WrongNumberOfBitsException(String message) {
        System.err.println(message);
    }
}
