package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnPublicKeyCredential;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.logic.FunctionSupport;
import net.shibboleth.shared.primitive.LoggerFactory;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;

import fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.EsupOtpContext;
import jakarta.servlet.http.HttpServletRequest;

import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl.EsupOtpEncoder.getWebAuthnObjectMapper;
import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.WEBAUTHN_METHOD;

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
public class EsupOtpExtractionTokenAction extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(EsupOtpExtractionTokenAction.class);
    
    /** Lookup strategy for username to use in resolving token seeds. */
    @Nonnull private Function<ProfileRequestContext, String> usernameLookupStrategy;
    
    /** Creation strategy for esup otp context. */
    @Nonnull private Function<AuthenticationContext, EsupOtpContext> esupOtpContextCreationStrategy;

    /** Lookup strategy for esup otp integration. */
    @Nonnull private Function<ProfileRequestContext, DefaultEsupOtpIntegration> esupOtpIntegrationLookupStrategy;
    
    /** Constructor. */
    public EsupOtpExtractionTokenAction() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
        esupOtpContextCreationStrategy = new ChildContextLookup<>(EsupOtpContext.class);

        esupOtpIntegrationLookupStrategy = FunctionSupport.constant(null);
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

        esupOtpContext.setPublicKeyCredentialAssertionResponse(null);
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

        if(esupOtpContext.getTransportChoose() == null) {
            log.warn("{} No transport choose", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if(WEBAUTHN_METHOD.equals(esupOtpContext.getTransportChoose())) {
            final String pkCredAssertionJson = extractPublicKeyCredentialAssertionJson(request);

            if (pkCredAssertionJson == null) {
                log.debug("{} No PublicKeyCredential with authenticator assertion response in request",getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }

            log.debug("{} Extracted publicKeyCredential : {}", getLogPrefix(), pkCredAssertionJson);

            try {
                esupOtpContext.setPublicKeyCredentialAssertionResponse(parseAssertionResponseJson(pkCredAssertionJson));
            } catch (JsonProcessingException e) {
                log.debug("{} Could not parse PublicKeyCredential response from request parameter '{}'",
                        getLogPrefix(), "publicKeyCredential", e);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            }

        } else {
            final String code =  extractCode(request);
            if (code == null) {
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }

            try {
                esupOtpContext.setTokenCode(Integer.valueOf(code));
                log.debug("Get token code : {}", esupOtpContext.getTokenCode());
            } catch (final NumberFormatException e) {
                log.warn("{} Exception converting code string to an integer", getLogPrefix(), e);
                authenticationContext.ensureSubcontext(AuthenticationErrorContext.class).getClassifiedErrors().add(
                        AuthnEventIds.INVALID_CREDENTIALS);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
            }
        }
    }



    /**
     * Gets the token code from the HTTP request.
     * First get from form request (input "token"),
     * Second get from header ("X-Shibboleth-ESUPOTP")
     * 
     * @param httpRequest current HTTP request
     * 
     * @return the token code, or null
     */
    @Nullable protected String extractCode(@Nonnull final HttpServletRequest httpRequest) {
        String code = httpRequest.getParameter("token");
        if(code == null) {
            code = httpRequest.getHeader("X-Shibboleth-ESUPOTP");
        }
        
        return code;
    }

    private String extractPublicKeyCredentialAssertionJson(HttpServletRequest httpRequest) {
        return httpRequest.getParameter("publicKeyCredential");
    }

    private WebAuthnPublicKeyCredential parseAssertionResponseJson(String json) throws JsonProcessingException {
        ObjectMapper objectMapper = getWebAuthnObjectMapper();
        return objectMapper.readValue(json, WebAuthnPublicKeyCredential.class);
    }
    
}
