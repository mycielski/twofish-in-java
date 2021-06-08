package twofish.exceptions;

/**
 * Thrown when a byte array does not meet the Twofish key requirements (for example when length is not 64/128/196/256 bit).
 */
public final class InvalidKeyException extends java.security.InvalidKeyException {
    public InvalidKeyException(String message) {
        System.err.println(message);
    }
}
