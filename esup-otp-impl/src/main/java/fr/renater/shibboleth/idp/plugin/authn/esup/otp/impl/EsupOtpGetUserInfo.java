package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import static fr.renater.shibboleth.idp.plugin.authn.esup.otp.util.EsupOtpUtils.SUPPORTED_METHODS_WITHOUT_TRANSPORT;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;

import fr.renater.shibboleth.esup.otp.DefaultEsupOtpIntegration;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClient;
import fr.renater.shibboleth.esup.otp.client.EsupOtpClientException;
import fr.renater.shibboleth.esup.otp.dto.user.EsupOtpUserInfoResponse;
import fr.renater.shibboleth.esup.otp.dto.user.UserMethods.UserMethod;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.EsupOtpContext;
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
 * An action that get esup otp user informations from a username from a lookup strategy,
 * creates a {@link EsupOtpContext}, and attaches it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#UNKNOWN_USERNAME}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null</pre>
 * @post <pre>AuthenticationContext.getSubcontext(EsupOtpContext.class) != null</pre>
 */
public class EsupOtpGetUserInfo extends AbstractAuthenticationAction {

	/** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(EsupOtpGetUserInfo.class);
    
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

	/**
	 * Constructor.
	 *
	 */
	public EsupOtpGetUserInfo() {
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
    protected void doExecute(@Nonnull ProfileRequestContext profileRequestContext,
    		@Nonnull AuthenticationContext authenticationContext) {
    	
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
        
        try {
        	log.debug("Get Esup otp user infos for username: {}", esupOtpContext.getUsername());
			EsupOtpUserInfoResponse userInfo = client.getUserInfos(esupOtpContext.getUsername());
			
			if(!"Ok".equals(userInfo.getCode())) {
				ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.UNKNOWN_USERNAME);
				return;
			}

            Set<String> choices = getChoices(esupOtpIntegration.getSupportedMethods(), userInfo);
            esupOtpContext.setEnabledChoices(choices);
            log.debug("Choices possible for {} : {}", esupOtpContext.getUsername(), esupOtpContext.getEnabledChoices());

            esupOtpContext.setConfiguredTransports(getTransports(userInfo));
            log.debug("Transports possible for {} : {}", esupOtpContext.getUsername(), esupOtpContext.getConfiguredTransports());
			
		} catch (EsupOtpClientException e) {
			log.warn("{} Client exception occured", getLogPrefix(), e);
			authenticationContext.ensureSubcontext(AuthenticationErrorContext.class).getClassifiedErrors().add(
                    CLIENT_EXCEPTION);
			ActionSupport.buildEvent(profileRequestContext, CLIENT_EXCEPTION);
		}
    }

    /**
     * Get available choices for user.
     * @param supportedMethods list of methods configured in properties
     * @param userInfo receive from esup-otp-api
     * @return list of active methods.
     */
    private Set<String> getChoices(Set<String> supportedMethods, EsupOtpUserInfoResponse userInfo) {
        Map<String, UserMethod> allUserMethodByType = userInfo.getUser().getMethods().getAll();
        Set<String> choices = new HashSet<>();
        allUserMethodByType.entrySet().stream()
            .filter(entry -> entry.getValue() != null)
            .filter(entry -> {
                if(supportedMethods.contains(entry.getKey()) && entry.getValue().isActive()) {
                    if(SUPPORTED_METHODS_WITHOUT_TRANSPORT.contains(entry.getKey())) {
                        return true;
                    } else {
                       return !entry.getValue().getTransports().isEmpty();
                    }
                }
                return false;
            })
            .forEach(entry -> {
                if(SUPPORTED_METHODS_WITHOUT_TRANSPORT.contains(entry.getKey())) {
                    choices.add(entry.getKey());
                } else {
                    Set<String> choiceWithTransport = entry.getValue().getTransports().stream()
                            .map(transport -> entry.getKey() + "." + transport)
                            .collect(Collectors.toSet());
                    choices.addAll(choiceWithTransport);
                }
            });
        return choices;
    }

    /**
     * Get transports with value null safe
     * @param userInfo receive from esup-otp-api
     * @return map of transport by type without null values
     */
    private Map<String, String> getTransports(EsupOtpUserInfoResponse userInfo) {
        return userInfo.getUser().getTransports().getAll().entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

}
