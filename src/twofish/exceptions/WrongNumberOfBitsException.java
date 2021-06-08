package twofish.exceptions;

public class WrongNumberOfBitsException extends IllegalArgumentException{
    public WrongNumberOfBitsException(String message) {
        super(message);
    }
}
