package fr.renater.shibboleth.esup.otp.client;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception to signal an error condition during execution of a Esup Otp
 * client.
 */
@ThreadSafe
public class EsupOtpClientInitializationException extends RuntimeException {

    /**
     * Default serialUID.
     */
    private static final long serialVersionUID = 279977852927336564L;

    /**
     * 
     * Constructor.
     *
     * @param message
     */
    public EsupOtpClientInitializationException(final String message) {
        super(message);
    }

    /**
     * 
     * Constructor.
     *
     * @param message
     * @param cause
     */
    public EsupOtpClientInitializationException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
