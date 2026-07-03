package fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.navigate;

import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import lombok.CustomLog;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.service.ReloadableService;

/**
 * A base class for functions that retrieve a single attribute value from the
 * {@link AttributeContext attribute context}.
 *
 * @param <T>
 *            the type of attribute value to return
 */
@CustomLog
public abstract class AbstractAttributeContextUserIdentityStrategy<T> extends AbstractIdentifiableInitializableComponent
        implements Function<ProfileRequestContext, T> {

    /** Lookup strategy for principal name. */
    @NonnullAfterInit
    private Function<ProfileRequestContext, String> principalNameLookupStrategy;

    @NonnullAfterInit
    private ReloadableService<AttributeResolver> attributeResolverService;

    /** Attribute ID to resolve. */
    @NonnullAfterInit
    @NotEmpty
    private String attributeId;

    /**
     * Set the attribute Id to extract the value from.
     *
     * @param id
     *            the attributeId.
     */
    public void setAttributeId(@Nullable final String id) {
        checkSetterPreconditions();
        attributeId = id;
    }

    /**
     * Get the attribute Id to extract the value from.
     *
     * @return the attributeId.
     */
    @Nullable
    @NotEmpty
    protected String getAttributeId() {
        checkComponentActive();
        return attributeId;
    }

    /**
     * Set lookup strategy for principal name.
     *
     * @param strategy
     *            lookup strategy
     */
    public void setPrincipalNameLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        checkSetterPreconditions();

        principalNameLookupStrategy = Constraint.isNotNull(strategy, "Principal name lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link AttributeContext} associated with
     * a given {@link ProfileRequestContext}.
     *
     * @param attrResolverService
     *            strategy used to locate the {@link AttributeContext} associated
     *            with a given {@link ProfileRequestContext}
     */
    public void setAttributeResolverService(@Nonnull final ReloadableService<AttributeResolver> attrResolverService) {
        checkSetterPreconditions();
        attributeResolverService = Constraint.isNotNull(attrResolverService, "AttributeResolverService cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (attributeResolverService == null) {
            throw new ComponentInitializationException("ReloadableService<AttributeResolver> cannot be null");
        }
        if (principalNameLookupStrategy == null) {
            throw new ComponentInitializationException("Principal name lookup strategy cannot be null");
        }
        if (attributeId == null) {
            throw new ComponentInitializationException("Attribute ID to resolve cannot be null or empty");
        }
    }

    /**
     * Get the attribute from either the filtered or unfiltered set of attributes
     * with the given attribute Id from the AttributeContext (if it exists).
     *
     * @param profileRequestContext
     *            the profile request context to locate the attribute context and
     *            the attribute from
     *
     * @return the IdPAttribute, or <code>null</code> if not found.
     */
    @Nullable
    protected IdPAttribute getAttribute(@Nonnull final ProfileRequestContext profileRequestContext) {

        checkComponentActive();

        final String principal = principalNameLookupStrategy.apply(profileRequestContext);
        if (principal == null) {
            log.error("Principal lookup strategy returned null value");
            return null;
        }

        final AttributeResolutionContext resolutionContext = buildResolutionContext(profileRequestContext, principal);
        assert attributeResolverService != null;
        resolutionContext.resolveAttributes(attributeResolverService);

        if (resolutionContext.getResolvedIdPAttributes().containsKey(attributeId)) {
            for (final IdPAttribute attribute : resolutionContext.getResolvedIdPAttributes().values()) {

                if (attribute != null && !attribute.getValues().isEmpty() && attribute.getId().equals(attributeId)) {
                    return attribute;
                }
            }
        } else {
            log.debug("Resolver did not return an IdPAttribute named {} for principal {}", attributeId, principal);
            return null;
        }

        log.trace("{}: Attribute '{}' could not be found", getId(), attributeId);
        return null;

    }

    /**
     * Build an {@link AttributeResolutionContext} to use.
     *
     * @param profileRequestContext
     *            profile request context
     * @param principal
     *            name of principal
     *
     * @return the attached context
     */
    @Nonnull
    private AttributeResolutionContext buildResolutionContext(
            @Nonnull final ProfileRequestContext profileRequestContext, @Nonnull @NotEmpty final String principal) {

        final AttributeResolutionContext resolutionContext = new AttributeResolutionContext();

        resolutionContext.setPrincipal(principal);
        assert attributeId != null;

        profileRequestContext.addSubcontext(resolutionContext, true);
        return resolutionContext;
    }
}
