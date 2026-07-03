package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import java.util.Arrays;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import fr.renater.shibboleth.esup.otp.client.EsupOtpClientException;
import fr.renater.shibboleth.esup.otp.config.EsupOtpRestTemplate;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Abstract esup otp client.
 */
@AllArgsConstructor
@Getter
public abstract class AbstractEsupOtpConnector {

    /** Rest template. */
    private final EsupOtpRestTemplate restTemplate;

    protected <T extends EsupOtpResponse> T get(@Nonnull final String uri, @Nonnull final Class<T> responseClass,
            @Nonnull final Object... uriVariables) throws EsupOtpClientException {
        try {

            final RequestEntity<?> request = RequestEntity.get(uri, uriVariables).build();

            final ResponseEntity<T> response = restTemplate.exchange(request, responseClass);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new EsupOtpClientException("Exception occured on call : " + uri + " with uri variables : "
                        + getUriVariables(uriVariables));
            }

            return response.getBody();
        } catch (final RestClientException e) {
            throw new EsupOtpClientException("RestClientException occured on call: " + uri, e);
        }
    }

    protected <T extends EsupOtpResponse> T post(@Nonnull final String uri, @Nonnull final Class<T> responseClass,
            final boolean throwException, @Nonnull final Object... uriVariables) throws EsupOtpClientException {
        try {

            final RequestEntity<?> request = RequestEntity.post(uri, uriVariables).build();

            final ResponseEntity<T> response = restTemplate.exchange(request, responseClass);

            if (throwException && !response.getStatusCode().is2xxSuccessful()) {
                throw new EsupOtpClientException("Exception occured on call : " + uri + " with uri variables : "
                        + getUriVariables(uriVariables));
            }

            return response.getBody();
        } catch (final RestClientException e) {
            throw new EsupOtpClientException("RestClientException occured on call: " + uri, e);
        }
    }

    protected void put(@Nonnull final String uri, @Nonnull final Object... uriVariables) throws EsupOtpClientException {
        try {

            final RequestEntity<?> request = RequestEntity.put(uri, uriVariables).build();

            final ResponseEntity<Void> response = restTemplate.exchange(request, Void.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new EsupOtpClientException("Exception occured on call : " + uri + " with uri variables : "
                        + getUriVariables(uriVariables));
            }
        } catch (final RestClientException e) {
            throw new EsupOtpClientException("RestClientException occured on call: " + uri, e);
        }
    }

    protected <T extends EsupOtpResponse> T delete(@Nonnull final String uri, @Nonnull final Class<T> responseClass,
            @Nonnull final Object... uriVariables) throws EsupOtpClientException {
        try {

            final RequestEntity<?> request = RequestEntity.delete(uri, uriVariables).build();

            final ResponseEntity<T> response = restTemplate.exchange(request, responseClass);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new EsupOtpClientException(
                        "Exception occured on call : " + uri + " with uri variables : " + getUriVariables());
            }

            return response.getBody();
        } catch (final RestClientException e) {
            throw new EsupOtpClientException("RestClientException occured on call: " + uri, e);
        }
    }

    private String getUriVariables(@Nonnull final Object... uriVariables) {
        return Arrays.stream(uriVariables).map(Object::toString).collect(Collectors.joining(","));
    }

}
