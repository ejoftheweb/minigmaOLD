package uk.co.platosys.minigma.exceptions;

public class NoDecryptionKeyException extends Exception {
    public NoDecryptionKeyException(String msg){
        super(msg);
    }
    public NoDecryptionKeyException(String msg, Throwable cause){
        super(msg, cause);
    }
}
