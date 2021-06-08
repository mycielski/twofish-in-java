package twofish.exceptions;

public class WrongNumberOfBitsException extends IllegalArgumentException{
    public WrongNumberOfBitsException(String message) {
        System.err.println(message);
    }
}
