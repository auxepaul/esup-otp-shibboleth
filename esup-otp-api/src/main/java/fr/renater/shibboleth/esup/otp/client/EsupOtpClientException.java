package fr.renater.shibboleth.esup.otp.client;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception to signal an error condition during execution of a Esup Otp
 * client.
 */
@ThreadSafe
public class EsupOtpClientException extends Exception {

    /**
     * Serial UID.
     */
    private static final long serialVersionUID = -4532220075956605233L;

    /**
     * 
     * Constructor.
     *
     * @param message
     */
    public EsupOtpClientException(final String message) {
        super(message);
    }

    /**
     * 
     * Constructor.
     *
     * @param message
     * @param cause
     */
    public EsupOtpClientException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
