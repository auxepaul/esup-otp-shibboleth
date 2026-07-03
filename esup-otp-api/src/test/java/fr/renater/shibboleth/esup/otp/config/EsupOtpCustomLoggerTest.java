
package fr.renater.shibboleth.esup.otp.config;

import org.testng.Assert;
import org.testng.annotations.Test;

import lombok.CustomLog;

@CustomLog
public class EsupOtpCustomLoggerTest {

    @Test
    public final void debugTest() {
        Assert.assertTrue(log.isDebugEnabled());
        log.debug("A simple debug test message");
    }

    @Test
    public final void infoTest() {
        Assert.assertTrue(log.isInfoEnabled());
        log.info("A simple info test message");
    }
}
