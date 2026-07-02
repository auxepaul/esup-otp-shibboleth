package fr.renater.shibboleth.esup.otp.config;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;

import lombok.CustomLog;

/**
 * Class to manage if the request is retryable or not.
 */
@CustomLog
public class RetryOverHttpError implements HttpRequestRetryStrategy {


    @Override
    public boolean retryRequest(final HttpRequest request, final IOException exception, final int execCount,
            final HttpContext context) {
        // Do not retry if over max retry count
        return execCount <= 5;
    }

    @Override
    public boolean retryRequest(final HttpResponse response, final int execCount, final HttpContext context) {
        // Do not retry if over max retry count
        if (execCount > 5) {
            return false;
        }

        try {
            final int responseCode = response.getCode();

            if (responseCode >= 500 && responseCode <= 599) {
                log.debug("Retrying for 5xx code");
                return true;
            } else if (responseCode == 429) {
                log.debug("Too many requests, retrying...");
                return true;
            }

        } catch (final Exception e) {
            log.debug("Caught Exception");
        }
        return false;
    }

    @Override
    public TimeValue getRetryInterval(final HttpResponse response, final int execCount, final HttpContext context) {
        return TimeValue.of(5000, TimeUnit.MILLISECONDS);
    }
}
