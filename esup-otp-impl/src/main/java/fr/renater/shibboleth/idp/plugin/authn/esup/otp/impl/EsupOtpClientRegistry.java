package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClient;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClientInitializationException;
import lombok.CustomLog;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.logic.Constraint;

/**
 * Esup otp client registry to get or create esup otp client.
 */
@ThreadSafe
@CustomLog
public class EsupOtpClientRegistry extends AbstractIdentifiableInitializableComponent {

    /** Registry of EsupOtpClient to EsupOtpIntegration. */
    @Nonnull
    @NonnullElements
    private final ConcurrentMap<DefaultEsupOtpIntegration, EsupOtpClient> clientRegistry;

    /** Function for creating a EsupOtpClient from a EsupOtpIntegration. */
    @Nonnull
    private final Function<DefaultEsupOtpIntegration, EsupOtpClient> clientRegistryMappingFunction;

    /**
     * Constructor.
     *
     */
    public EsupOtpClientRegistry() {
        clientRegistry = new ConcurrentHashMap<>(1);
        clientRegistryMappingFunction = new CreateNewClientMappingFunction();
    }

    /**
     * Get or create esup otp connector.
     *
     * @param integration
     * @return esup otp connector
     */
    @Nonnull
    public EsupOtpClient getClientOrCreate(@Nonnull final DefaultEsupOtpIntegration integration) {
        Constraint.isNotNull(integration, "EsupOtp integration can not be null");

        final EsupOtpClient client = clientRegistry.computeIfAbsent(integration, clientRegistryMappingFunction);
        log.trace("Client registry returning the EsupOtpConnector instance of type '{}'",
                client.getClass().getCanonicalName());
        return client;
    }

    /**
     * A function for creating a new Esup otp client from the configured client
     * factory for the given EsupOtp integration. throws a
     * {@link EsupOtpClientInitializationException} if the factory can not create
     * the client.
     */
    @ThreadSafe
    private final class CreateNewClientMappingFunction implements Function<DefaultEsupOtpIntegration, EsupOtpClient> {
        @Override
        @Nonnull
        public EsupOtpClient apply(@Nullable final DefaultEsupOtpIntegration integration) {
            assert integration != null;
            return new EsupOtpClientImpl(integration);
        }

    }

}
