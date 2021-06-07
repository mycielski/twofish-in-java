package Twofish;

public final class InvalidKeyException extends java.security.InvalidKeyException {
    public InvalidKeyException(String message) {
        System.err.println(message);
    }
}
