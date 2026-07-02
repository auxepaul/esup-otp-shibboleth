package fr.renater.shibboleth.esup.otp.config;

import java.io.IOException;

import javax.annotation.Nonnull;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import lombok.AllArgsConstructor;

/**
 * Esup otp http client interceptor for add Authorization header.
 */
@Order(1)
@AllArgsConstructor
public class EsupOtpAuthInterceptor implements ClientHttpRequestInterceptor {

    /**
     * apiPassword to request esup-otp-api.
     */
    private final String apiPassword;

    /**
     * tenant to request esup-otp-api.
     */
    private final String tenant;

    /**
     * Intercept request and add default authorization header.
     * 
     * <p>
     * {@inheritDoc}
     * </p>
     */
    public @Nonnull ClientHttpResponse intercept(@Nonnull final HttpRequest request, @Nonnull final byte[] body,
            @Nonnull final ClientHttpRequestExecution execution) throws IOException {
        // Add default authorization header
        request.getHeaders().add("Authorization", "Bearer " + apiPassword);
        // Add custom header to identify tenant
        request.getHeaders().add("x-tenant", tenant);
        return execution.execute(request, body);
    }
}
