package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.PASSCODE_GRID_METHOD;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;

import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClient;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClientException;
import fr.renater.shibboleth.esup.otp.client.EsupOtpUriConstants;
import fr.renater.shibboleth.esup.otp.config.EsupOtpRestTemplate;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpUsersResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyWebAuthnRequest;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyWebAuthnResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpPasscodeGridResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpWebauthnResponse;
import fr.renater.shibboleth.esup.otp.dto.user.EsupOtpUserInfoResponse;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl.EsupOtpEncoder;
import lombok.CustomLog;

/**
 * Esup otp api connector implementation.
 */
@SuppressWarnings("unused")
@CustomLog
public class EsupOtpClientImpl extends AbstractEsupOtpConnector implements EsupOtpClient {

    private final EsupOtpEncoder encoder;

    /**
     * Constructor.
     *
     * @param integration
     *            DefaultEsupOtpIntegration.
     */
    public EsupOtpClientImpl(final DefaultEsupOtpIntegration integration) {
        super(new EsupOtpRestTemplate(integration));

        this.encoder = new EsupOtpEncoder(integration.getUsersSecret());
    }

    /** {@inheritDoc} */
    public EsupOtpUserInfoResponse getOtpUserInfos(final String uid) throws EsupOtpClientException {
        try {
            final String hash = encoder.getUserHash(uid);
            final EsupOtpUserInfoResponse response = get(EsupOtpUriConstants.Public.GET_USER_INFOS,
                    EsupOtpUserInfoResponse.class, uid, hash);

            log.debug("getOtpUserInfos method");

            return response;
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new EsupOtpClientException("Get user hash failed", e);
        }
    }

    /** {@inheritDoc} */
    public EsupOtpResponse postSendMessage(final String uid, final String method, final String transport)
            throws EsupOtpClientException {
        try {
            final String hash = encoder.getUserHash(uid);
            final EsupOtpResponse response = post(EsupOtpUriConstants.Public.POST_MESSAGE, EsupOtpResponse.class, true,
                    uid, method, transport, hash);

            log.debug("postSendMessage method");

            return response;
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new EsupOtpClientException("Get user hash failed", e);
        }
    }

    @Override
    public EsupOtpPasscodeGridResponse postGeneratePasscodeGridChallenge(final String uid)
            throws EsupOtpClientException {
        try {
            final String hash = encoder.getUserHash(uid);
            final EsupOtpPasscodeGridResponse response = post(EsupOtpUriConstants.Public.POST_MESSAGE,
                    EsupOtpPasscodeGridResponse.class, true, uid, PASSCODE_GRID_METHOD, PASSCODE_GRID_METHOD, hash);

            log.debug("postGeneratePassCodeGridChallenge method");

            return response;
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new EsupOtpClientException("Get user hash failed", e);
        }
    }

    @Override
    public EsupOtpWebauthnResponse postGenerateWebauthnSecret(final String uid) throws EsupOtpClientException {
        try {
            final String hash = encoder.getUserHash(uid);
            return post(EsupOtpUriConstants.Public.POST_GENERATE_WEBAUTHN, EsupOtpWebauthnResponse.class, true, uid,
                    hash);
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new EsupOtpClientException("Get user hash failed", e);
        }
    }

    /** {@inheritDoc} */
    public EsupOtpUserInfoResponse getUserInfos(final String uid) throws EsupOtpClientException {
        final EsupOtpUserInfoResponse response = get(EsupOtpUriConstants.Protected.GET_USER_INFOS,
                EsupOtpUserInfoResponse.class, uid);

        log.debug("getUserInfos method");

        return response;
    }

    /** {@inheritDoc} */
    public EsupOtpResponse getTransportTest(final String uid, final String transport) throws EsupOtpClientException {
        return get(EsupOtpUriConstants.Protected.GET_TRANSPORT_TEST, EsupOtpResponse.class, uid, transport);
    }

    /** {@inheritDoc} */
    public void putActivate(final String uid, final String method) throws EsupOtpClientException {
        put(EsupOtpUriConstants.Protected.PUT_ACTIVATE, uid, method);
    }

    /** {@inheritDoc} */
    public void putDeactivate(final String uid, final String method) throws EsupOtpClientException {
        put(EsupOtpUriConstants.Protected.PUT_DEACTIVATE, uid, method);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse postConfirmActivate(final String uid, final String method, final String activationCode)
            throws EsupOtpClientException {
        return post(EsupOtpUriConstants.Protected.POST_CONFIRM_ACTIVATE, EsupOtpResponse.class, true, uid, method,
                activationCode);
    }

    /** {@inheritDoc} */
    public void putUpdateTransport(final String uid, final String transport, final String newTransport)
            throws EsupOtpClientException {
        put(EsupOtpUriConstants.Protected.PUT_UPDATE_TRANSPORT, uid, transport, newTransport);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse getNewTransportTest(final String uid, final String transport, final String newTransport)
            throws EsupOtpClientException {
        return get(EsupOtpUriConstants.Protected.GET_NEW_TRANSPORT_TEST, EsupOtpResponse.class, uid, transport,
                newTransport);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse postSecret(final String uid, final String method) throws EsupOtpClientException {
        return post(EsupOtpUriConstants.Protected.POST_SECRET, EsupOtpResponse.class, true, uid, method);
    }

    /** {@inheritDoc} */
    public boolean postVerify(final String uid, final String otp) throws EsupOtpClientException {
        final EsupOtpVerifyResponse response = post(EsupOtpUriConstants.Protected.POST_VERIFY,
                EsupOtpVerifyResponse.class, false, uid, otp);
        final boolean valid = response != null && "Ok".equals(response.getCode());

        log.debug("postVerify method, valid token : {}", valid);

        return valid;
    }

    /** {@inheritDoc} */
    public boolean postVerifyWebauthn(final String uid, @Nonnull final EsupOtpVerifyWebAuthnRequest body)
            throws EsupOtpClientException {
        try {
            final String hash = encoder.getUserHash(uid);
            final RequestEntity<?> request = RequestEntity
                    .post(EsupOtpUriConstants.Public.POST_VERIFY_WEBAUTHN, uid, hash)
                    .contentType(MediaType.APPLICATION_JSON).body(body);

            final ResponseEntity<EsupOtpVerifyWebAuthnResponse> response = getRestTemplate().exchange(request,
                    EsupOtpVerifyWebAuthnResponse.class);

            log.debug("postVerifyAuthn method");

            if (response.getStatusCode().is2xxSuccessful()) {
                return true;
            }

            throw new EsupOtpClientException("Exception occured on call : "
                    + EsupOtpUriConstants.Public.POST_VERIFY_WEBAUTHN + " with uri variables : " + uid);
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new EsupOtpClientException("Get user hash failed", e);
        } catch (final RestClientException e) {
            throw new EsupOtpClientException(
                    "RestClientException occured on call: " + EsupOtpUriConstants.Public.POST_VERIFY_WEBAUTHN, e);
        }
    }

    /** {@inheritDoc} */
    public EsupOtpResponse deleteTransport(final String uid, final String transport) throws EsupOtpClientException {
        return delete(EsupOtpUriConstants.Protected.DELETE_TRANSPORT, EsupOtpResponse.class, uid, transport);
    }

    /** {@inheritDoc} */
    public EsupOtpUsersResponse getUsers() throws EsupOtpClientException {
        return get(EsupOtpUriConstants.Admin.GET_USERS, EsupOtpUsersResponse.class);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse getUser(final String uid) throws EsupOtpClientException {
        return get(EsupOtpUriConstants.Admin.GET_USER, EsupOtpResponse.class, uid);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse getMethods(final String uid) throws EsupOtpClientException {
        return get(EsupOtpUriConstants.Admin.GET_METHODS, EsupOtpResponse.class, uid);
    }

    /** {@inheritDoc} */
    public void putActivateMethodTransport(final String method, final String transport) throws EsupOtpClientException {
        put(EsupOtpUriConstants.Admin.PUT_ACTIVATE_TRANSPORT, method, transport);
    }

    /** {@inheritDoc} */
    public void putDeactivateMethodTransport(final String method, final String transport)
            throws EsupOtpClientException {
        put(EsupOtpUriConstants.Admin.PUT_DEACTIVATE_TRANSPORT, method, transport);
    }

    /** {@inheritDoc} */
    public void putActivateMethod(final String method) throws EsupOtpClientException {
        put(EsupOtpUriConstants.Admin.PUT_ACTIVATE, method);
    }

    /** {@inheritDoc} */
    public void putDeactivateMethod(final String method) throws EsupOtpClientException {
        put(EsupOtpUriConstants.Admin.PUT_DEACTIVATE_TRANSPORT, method);
    }

    /** {@inheritDoc} */
    public EsupOtpResponse deleteMethodSecret(final String uid, final String method) throws EsupOtpClientException {
        return delete(EsupOtpUriConstants.Admin.DELETE_SECRET, EsupOtpResponse.class, uid, method);
    }

}
