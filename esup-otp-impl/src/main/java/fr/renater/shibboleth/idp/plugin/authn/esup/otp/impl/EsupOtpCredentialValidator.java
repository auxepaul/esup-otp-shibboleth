package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.WEBAUTHN_METHOD;

import java.security.Principal;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;

import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.esup.otp.EsupOtpPrincipal;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClient;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.EsupOtpContext;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnPublicKeyCredential;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.mapper.WebauthnMapper;
import lombok.CustomLog;
import net.shibboleth.idp.authn.AbstractCredentialValidator;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.CredentialValidator;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;

/**
 * A {@link CredentialValidator} that checks {@link EsupOtpContext}.
 */
@CustomLog
public class EsupOtpCredentialValidator extends AbstractCredentialValidator {

    /** Lookup strategy for EsupOtp context. */
    @Nonnull
    private Function<AuthenticationContext, EsupOtpContext> esupOtpContextLookup;

    /** Lookup strategy for esup otp integration. */
    @Nonnull
    private Function<ProfileRequestContext, DefaultEsupOtpIntegration> esupOtpIntegrationLookupStrategy;

    /** A regular expression to apply for acceptance testing. */
    @Nullable
    private Pattern matchExpression;

    /**
     * The registry for locating the EsupOtpClient for the established integration.
     */
    @NonnullAfterInit
    private EsupOtpClientRegistry clientRegistry;

    /** Constructor. */
    public EsupOtpCredentialValidator() {
        esupOtpContextLookup = new ChildContextLookup<>(EsupOtpContext.class);

        esupOtpIntegrationLookupStrategy = FunctionSupport.constant(null);
    }

    /**
     * Set the EsupOtp client registry.
     *
     * @param esupOtpClientRegistry
     *            the registry
     */
    public void setClientRegistry(@Nonnull final EsupOtpClientRegistry esupOtpClientRegistry) {
        checkSetterPreconditions();

        clientRegistry = Constraint.isNotNull(esupOtpClientRegistry, "EsupOtpClient registry can not be null");
    }

    /**
     * Set the lookup strategy to locate the {@link EsupOtpContext}.
     *
     * @param strategy
     *            lookup strategy
     */
    public void setEsupOtpContextLookupStrategy(
            @Nonnull final Function<AuthenticationContext, EsupOtpContext> strategy) {
        checkSetterPreconditions();

        esupOtpContextLookup = Constraint.isNotNull(strategy, "EsupOtpContext lookup strategy cannot be null");
    }

    /**
     * Set the lookup strategy to locate/create the {@link EsupOtpContext}.
     *
     * @param strategy
     *            lookup/creation strategy
     */
    public void setEsupOtpIntegrationLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, DefaultEsupOtpIntegration> strategy) {
        checkSetterPreconditions();

        esupOtpIntegrationLookupStrategy = Constraint.isNotNull(strategy,
                "EsupOtpIntegration creation strategy cannot be null");
    }

    /**
     * Set a matching expression to apply to the username for acceptance.
     *
     * @param expression
     *            a matching expression
     */
    public void setMatchExpression(@Nullable final Pattern expression) {
        checkSetterPreconditions();

        matchExpression = expression;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (clientRegistry == null) {
            throw new ComponentInitializationException("EsupOtp Client Registry cannot be null");
        }
    }

    // Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    protected Subject doValidate(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext, @Nullable final WarningHandler warningHandler,
            @Nullable final ErrorHandler errorHandler) throws Exception {

        final String logPrefix = getLogPrefix();

        final EsupOtpContext esupOtpContext = esupOtpContextLookup.apply(authenticationContext);
        if (esupOtpContext == null) {
            log.info("{} No EsupOtpContext available", logPrefix);
            if (errorHandler != null) {
                errorHandler.handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                        AuthnEventIds.NO_CREDENTIALS);
            }
            throw new LoginException(AuthnEventIds.NO_CREDENTIALS);
        }

        final DefaultEsupOtpIntegration esupOtpIntegration = esupOtpIntegrationLookupStrategy.apply(profileRequestContext);
        if (esupOtpIntegration == null) {
            log.warn("{} No EsupOtpIntegration returned by lookup strategy", logPrefix);
            if (errorHandler != null) {
                errorHandler.handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                        AuthnEventIds.NO_CREDENTIALS);
            }
            throw new LoginException(AuthnEventIds.NO_CREDENTIALS);
        }

        final EsupOtpClient client = clientRegistry.getClientOrCreate(esupOtpIntegration);

        final String username = esupOtpContext.getUsername();
        if (username == null) {
            log.info("{} No username available within EsupOtpContext", logPrefix);
            if (errorHandler != null) {
                errorHandler.handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                        AuthnEventIds.NO_CREDENTIALS);
            }
            throw new LoginException(AuthnEventIds.NO_CREDENTIALS);
        }

        final WebAuthnPublicKeyCredential assertion = esupOtpContext.getPublicKeyCredentialAssertionResponse();
        final String tokenCode = esupOtpContext.getTokenCode();
        if (WEBAUTHN_METHOD.equals(esupOtpContext.getMethodChoice())) {
            if (assertion == null) {
                log.warn("{} No PublicKeyCredential with authenticator assertion found, can not authenticate '{}'",
                        logPrefix, username);
                if (errorHandler != null) {
                    errorHandler.handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                            AuthnEventIds.NO_CREDENTIALS);
                }
                throw new LoginException(AuthnEventIds.NO_CREDENTIALS);
            }
        } else {
            if (tokenCode == null || tokenCode.isBlank()) {
                log.warn("{} No tokencode available within EsupOtpContext", logPrefix);
                if (errorHandler != null) {
                    errorHandler.handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                            AuthnEventIds.NO_CREDENTIALS);
                }
                throw new LoginException(AuthnEventIds.NO_CREDENTIALS);
            }
        }

        if (matchExpression != null && !matchExpression.matcher(username).matches()) {
            log.debug("{} Username '{}' did not match expression", logPrefix, username);
            return null;
        }

        log.debug("{} Attempting to authenticate token code for '{}' ", logPrefix, username);

        try {
            if (WEBAUTHN_METHOD.equals(esupOtpContext.getMethodChoice())) {
                if (client.postVerifyWebauthn(username, WebauthnMapper.INSTANCE.toEsupOtpVerifyWebAuthnRequestDto(assertion))) {
                    log.info("{} Login by '{}' with webauthn succeeded", logPrefix, username);
                    return populateSubject(new Subject(), esupOtpContext, esupOtpIntegration);
                } else {
                    log.info("{} Login by '{}' with webauthn failed", logPrefix, username);
                }
            } else {
                if (tokenCode.matches("\\d+")) {
                    if(client.postVerify(username, tokenCode)) {
                        log.info("{} Login by '{}' succeeded", logPrefix, username);
                        return populateSubject(new Subject(), esupOtpContext, esupOtpIntegration);
                    } else {
                        log.info("{} Login by '{}' failed", logPrefix, username);
                    }
                } else {
                    log.warn("{} the tokencode is not an integer", logPrefix);
                }
            }
            throw new LoginException(AuthnEventIds.INVALID_CREDENTIALS);
        } catch (final Exception e) {
            log.info("{} Login by '{}' failed", logPrefix, username);
            if (errorHandler != null) {
                errorHandler.handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.INVALID_CREDENTIALS);
            }
            throw e;
        }
    }
    // Checkstyle: CyclomaticComplexity ON

    /**
     * Decorate the subject with "standard" content from the validation.
     *
     * @param subject
     *            the subject being returned
     * @param esupOtpContext
     *            the EsupOtp context being validated
     * @param esupOtpIntegration
     *            the EsupOtp integration
     *
     * @return the decorated subject
     */
    @Nonnull
    protected Subject populateSubject(@Nonnull final Subject subject, @Nonnull final EsupOtpContext esupOtpContext,
            @Nonnull final DefaultEsupOtpIntegration esupOtpIntegration) {

        final String username = esupOtpContext.getUsername();
        // Checked earlier.
        assert username != null;
        subject.getPrincipals().add(new EsupOtpPrincipal(username));
        final Set<Principal> princs = esupOtpIntegration.getSupportedPrincipals(Principal.class);
        subject.getPrincipals().addAll(princs);
        return subject;
    }

}
