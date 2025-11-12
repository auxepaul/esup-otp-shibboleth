package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.BYPASS_METHOD;
import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.SUPPORTED_METHODS_WITHOUT_TRANSPORT;
import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.TOTP_METHOD;
import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.WEBAUTHN_METHOD;

import java.util.Map;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;

import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClient;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClientException;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpWebauthnResponse;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.EsupOtpContext;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.mapper.WebauthnMapper;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * An action that derives a username from a lookup strategy, get otp code from form or header,
 * creates a {@link EsupOtpContext}, and attaches it to the {@link AuthenticationContext}.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null</pre>
 * @post <pre>AuthenticationContext.getSubcontext(EsupOtpContext.class) != null</pre>
 */
public class EsupOtpExtractionAction extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(EsupOtpExtractionAction.class);

    private static final String CLIENT_EXCEPTION = "ClientException";

    /** Lookup strategy for username to use in resolving token seeds. */
    @Nonnull private Function<ProfileRequestContext, String> usernameLookupStrategy;

    /** Creation strategy for esup otp context. */
    @Nonnull private Function<AuthenticationContext, EsupOtpContext> esupOtpContextCreationStrategy;

    /** Lookup strategy for esup otp integration. */
    @Nonnull private Function<ProfileRequestContext, DefaultEsupOtpIntegration> esupOtpIntegrationLookupStrategy;

    /** The registry for locating the EsupOtpClient for the established integration.*/
    @NonnullAfterInit
    private EsupOtpClientRegistry clientRegistry;

    /** Constructor. */
    public EsupOtpExtractionAction() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
        esupOtpContextCreationStrategy = new ChildContextLookup<>(EsupOtpContext.class, true);

        esupOtpIntegrationLookupStrategy = FunctionSupport.constant(null);
    }

    /**
     * Set the EsupOtp client registry.
     *
     * @param esupOtpClientRegistry the registry
     */
    public void setClientRegistry(@Nonnull final EsupOtpClientRegistry esupOtpClientRegistry) {
        checkSetterPreconditions();

        clientRegistry = Constraint.isNotNull(esupOtpClientRegistry,"EsupOtpClient registry can not be null");
    }

    /**
     * Set the lookup strategy to use for the username to use in resolving token seeds.
     *
     * @param strategy lookup strategy
     */
    public void setUsernameLookupStrategy(@Nonnull final Function<ProfileRequestContext,String> strategy) {
        checkSetterPreconditions();

        usernameLookupStrategy = Constraint.isNotNull(strategy, "Username lookup strategy cannot be null");
    }

    /**
     * Set the lookup strategy to locate/create the {@link EsupOtpContext}.
     *
     * @param strategy lookup/creation strategy
     */
    public void setEsupOtpContextCreationStrategy(
            @Nonnull final Function<AuthenticationContext, EsupOtpContext> strategy) {
        checkSetterPreconditions();

        esupOtpContextCreationStrategy = Constraint.isNotNull(strategy,
                "EsupOtpContext creation strategy cannot be null");
    }

    /**
     * Set the lookup strategy to locate/create the {@link EsupOtpContext}.
     *
     * @param strategy lookup/creation strategy
     */
    public void setEsupOtpIntegrationLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, DefaultEsupOtpIntegration> strategy) {
        checkSetterPreconditions();

        esupOtpIntegrationLookupStrategy = Constraint.isNotNull(strategy, 
                "EsupOtpIntegration creation strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (clientRegistry ==  null) {
            throw new ComponentInitializationException("EsupOtp Client Registry cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        // Clear error state.
        authenticationContext.removeSubcontext(AuthenticationErrorContext.class);

        final EsupOtpContext esupOtpContext = esupOtpContextCreationStrategy.apply(authenticationContext);
        if (esupOtpContext == null) {
            log.warn("{} Unable to create esup otp context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }

        final DefaultEsupOtpIntegration esupOtpIntegration = esupOtpIntegrationLookupStrategy.apply(profileRequestContext);
        if (esupOtpIntegration == null) {
            log.warn("{} No EsupOtpIntegration returned by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }

        final EsupOtpClient client = clientRegistry.getClientOrCreate(esupOtpIntegration);

        esupOtpContext.setTokenCode(null);

        // Fill in username if not set.
        if (esupOtpContext.getUsername() == null) {
            final String username = usernameLookupStrategy.apply(profileRequestContext);
            if (username == null) {
                log.warn("{} No principal name available", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            esupOtpContext.setUsername(username);
        }

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.warn("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        // In case of resend we reuse transport already chosen.
        if (esupOtpContext.getTransportChoose() == null) {
            final String transport = extractTransport(request);
            if(transport == null) {
                log.warn("{} No transport can be extracted from HttpServletRequest", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            log.debug("Transport choose : {}", transport);
            esupOtpContext.setTransportChoose(transport);
        } else {
            log.debug("Reuse transport choose : {}", esupOtpContext.getTransportChoose());
        }

        Map<String, String> configuredTransports = esupOtpContext.getConfiguredTransports();
        if(configuredTransports == null || configuredTransports.isEmpty()) {
            log.debug("{} Profile action does not contain configured transports", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        try {
            if(WEBAUTHN_METHOD.equals(esupOtpContext.getTransportChoose())) {
                EsupOtpWebauthnResponse response = client.postGenerateWebauthnSecret(esupOtpContext.getUsername());
                esupOtpContext.setWebauthnCredentialRequestOptions(WebauthnMapper.INSTANCE.toWebAuthnDto(response));
                log.debug("Set WebauthnCredentialRequestOptions : {}", esupOtpContext.getWebauthnCredentialRequestOptions());
            } else if(!BYPASS_METHOD.equals(esupOtpContext.getTransportChoose()) && !TOTP_METHOD.equals(esupOtpContext.getTransportChoose())) {
                if(esupOtpContext.getSendCounter() > esupOtpIntegration.getMaxRetry()) {
                    log.warn("{} send message already tried {}", getLogPrefix(), esupOtpContext.getSendCounter());
                } else {
                    if(SUPPORTED_METHODS_WITHOUT_TRANSPORT.contains(esupOtpContext.getTransportChoose())) {
                        client.postSendMessage(esupOtpContext.getUsername(), esupOtpContext.getTransportChoose(), esupOtpContext.getTransportChoose());
                    } else {
                        String[] method_transport = esupOtpContext.getTransportChoose().split("\\.");
                        client.postSendMessage(esupOtpContext.getUsername(), method_transport[0], method_transport[1]);
                    }
                    esupOtpContext.setSendCounter(esupOtpContext.getSendCounter() + 1);
                }
            }
        } catch (EsupOtpClientException e) {
            log.error("{} Send message with option '{}' to '{}' failed", getLogPrefix(), esupOtpContext.getTransportChoose(), esupOtpContext.getUsername(), e);
            authenticationContext.ensureSubcontext(AuthenticationErrorContext.class).getClassifiedErrors().add(
                    CLIENT_EXCEPTION);
            ActionSupport.buildEvent(profileRequestContext, CLIENT_EXCEPTION);
        }
    }

    /**
     * Gets the transport choose from the HTTP request.
     * First get from form request (input "transportchoose"),
     *
     * @param httpRequest current HTTP request
     *
     * @return the token code, or null
     */
    @Nullable protected String extractTransport(@Nonnull final HttpServletRequest httpRequest) {
        return httpRequest.getParameter("transportchoose");
    }

}
