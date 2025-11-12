package fr.renater.shibboleth.esup.otp.client;

import javax.annotation.Nonnull;

import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpUsersResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyWebAuthnRequest;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpWebauthnResponse;
import fr.renater.shibboleth.esup.otp.dto.user.EsupOtpUserInfoResponse;

/**
 * Esup otp api connector.
 */
public interface EsupOtpClient {

    //----------------------------------------------------------------
    // Otp calls.
    //----------------------------------------------------------------

    /**
     * Retrieves detailed OTP user information for the given user.
     *
     * @param uid The unique identifier of the user.
     * @return EsupOtpUserInfoResponse The response object containing the OTP user information.
     * @throws EsupOtpClientException If an error occurs while retrieving the information.
     */
    EsupOtpUserInfoResponse getOtpUserInfos(String uid) throws EsupOtpClientException;

    /**
     * Sends a message using the specified method and transport for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method used for sending the message.
     * @param transport The transport mechanism used for sending the message.
     * @return EsupOtpResponse The response object containing the result of the message send operation.
     * @throws EsupOtpClientException If an error occurs while sending the message.
     */
    EsupOtpResponse postSendMessage(String uid, String method, String transport)
            throws EsupOtpClientException;

    /**
     * Generates a WebAuthn secret for the specified user.
     *
     * @param uid The unique identifier of the user.
     * @return EsupOtpWebauthnResponse The response object containing the result of the WebAuthn secret generation.
     * @throws EsupOtpClientException If an error occurs during the secret generation process.
     */
    EsupOtpWebauthnResponse postGenerateWebauthnSecret(String uid) throws EsupOtpClientException;


    //----------------------------------------------------------------
    // Protected calls.
    //----------------------------------------------------------------

    /**
     * Retrieves detailed OTP information for a specific user.
     *
     * @param uid The unique identifier of the user.
     * @return EsupOtpUserInfoResponse The response object containing the user's OTP information.
     * @throws EsupOtpClientException If an error occurs while retrieving the user's information.
     */
    EsupOtpUserInfoResponse getUserInfos(String uid) throws EsupOtpClientException;

    /**
     * Performs a transport test for a specific transport method associated with a user.
     *
     * @param uid The unique identifier of the user.
     * @param transport The transport method to be tested.
     * @return EsupOtpResponse The response object containing the result of the transport test.
     * @throws EsupOtpClientException If an error occurs during the transport test.
     */
    EsupOtpResponse getTransportTest(String uid, String transport) throws EsupOtpClientException;

    /**
     * Activates a specific OTP method for a user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method to be activated.
     * @throws EsupOtpClientException If an error occurs during the activation process.
     */
    void putActivate(String uid, String method) throws EsupOtpClientException;

    /**
     * Deactivates a specified method for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method to be deactivated.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    void putDeactivate(String uid, String method) throws EsupOtpClientException;

    /**
     * Confirms the activation of a specified method using an activation code for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method to be activated.
     * @param activationCode The activation code used to confirm the activation.
     * @return EsupOtpResponse The response object containing the result of the activation.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    EsupOtpResponse postConfirmActivate(String uid, String method, String activationCode) throws EsupOtpClientException;

    /**
     * Updates the user's transport method with a new transport method.
     *
     * @param uid The unique identifier of the user.
     * @param transport The current transport method.
     * @param newTransport The new transport method to replace the old one.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    void putUpdateTransport(String uid, String transport, String newTransport) throws EsupOtpClientException;

    /**
     * Tests the newly updated transport method for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param transport The current transport method.
     * @param newTransport The newly updated transport method being tested.
     * @return EsupOtpResponse The response object containing the result of the test.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    EsupOtpResponse getNewTransportTest(String uid, String transport, String newTransport) 
            throws EsupOtpClientException;

    /**
     * Sets or updates the secret for a specified method for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method for which the secret is being set.
     * @return EsupOtpResponse The response object containing the result of the secret update.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    EsupOtpResponse postSecret(String uid, String method) throws EsupOtpClientException;

    /**
     * Verifies the user's identity using an OTP (one-time password).
     *
     * @param uid The unique identifier of the user.
     * @param otp The one-time password used for verification.
     * @return boolean Returns true if verification is successful, otherwise false.
     * @throws EsupOtpClientException If an error occurs during the verification process.
     */
    boolean postVerify(String uid, String otp) throws EsupOtpClientException;

    /**
     * Verifies the WebAuthn authentication for the specified user.
     *
     * @param uid The unique identifier of the user.
     * @param body The request body for post verify webauthn.
     * @return boolean Returns true if the WebAuthn verification is successful; otherwise, false.
     * @throws EsupOtpClientException If an error occurs during the WebAuthn verification process.
     */
    boolean postVerifyWebauthn(String uid, @Nonnull EsupOtpVerifyWebAuthnRequest body) throws EsupOtpClientException;

    /**
     * Deletes a specified transport method for the given user.
     *
     * @param uid The unique identifier of the user.
     * @param transport The transport method to be deleted.
     * @return EsupOtpResponse The response object containing the result of the deletion.
     * @throws EsupOtpClientException If an error occurs during the process.
     */
    EsupOtpResponse deleteTransport(String uid, String transport) throws EsupOtpClientException;



    //----------------------------------------------------------------
    // Admin calls.
    //----------------------------------------------------------------

    /**
     * Retrieves a list of all OTP users.
     *
     * @return EsupOtpUsersResponse The response object containing the list of OTP users.
     * @throws EsupOtpClientException If an error occurs while retrieving the users.
     */
    EsupOtpUsersResponse getUsers() throws EsupOtpClientException;

    /**
     * Retrieves detailed information for a specific user.
     *
     * @param uid The unique identifier of the user.
     * @return EsupOtpResponse The response object containing the user's information.
     * @throws EsupOtpClientException If an error occurs while retrieving the user's information.
     */
    EsupOtpResponse getUser(String uid) throws EsupOtpClientException;

    /**
     * Retrieves all OTP methods associated with a specific user.
     *
     * @param uid The unique identifier of the user.
     * @return EsupOtpResponse The response object containing the list of methods.
     * @throws EsupOtpClientException If an error occurs while retrieving the methods.
     */
    EsupOtpResponse getMethods(String uid) throws EsupOtpClientException;

    /**
     * Activates a specific transport for a method.
     *
     * @param method The method associated with the transport.
     * @param transport The transport to be activated.
     * @throws EsupOtpClientException If an error occurs while retrieving the methods.
     */
    void putActivateMethodTransport(String method, String transport) throws EsupOtpClientException;

    /**
     * Deactivates a specific transport for a method.
     *
     * @param method The method associated with the transport.
     * @param transport The transport to be deactivated.
     * @throws EsupOtpClientException If an error occurs while retrieving the methods.
     */
    void putDeactivateMethodTransport(String method, String transport) throws EsupOtpClientException;

    /**
     * Activates a specific method.
     *
     * @param method The method to be activated.
     * @throws EsupOtpClientException If an error occurs while retrieving the methods.
     */
    void putActivateMethod(String method) throws EsupOtpClientException;

    /**
     * Deactivates a specific method.
     *
     * @param method The method to be deactivated.
     * @throws EsupOtpClientException If an error occurs while retrieving the methods.
     */
    void putDeactivateMethod(String method) throws EsupOtpClientException;

    /**
     * Deletes the secret associated with a specific method for a user.
     *
     * @param uid The unique identifier of the user.
     * @param method The method for which the secret is being deleted.
     * @return EsupOtpResponse The response object containing the result of the deletion.
     * @throws EsupOtpClientException If an error occurs during the deletion process.
     */
    EsupOtpResponse deleteMethodSecret(String uid, String method) throws EsupOtpClientException;
}
