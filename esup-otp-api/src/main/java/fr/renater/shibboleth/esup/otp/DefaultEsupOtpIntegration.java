package fr.renater.shibboleth.esup.otp;

import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.Subject;

import lombok.CustomLog;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Synchronized;

import net.shibboleth.idp.authn.principal.PrincipalSupportingComponent;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.annotation.constraint.NotLive;
import net.shibboleth.shared.annotation.constraint.Unmodifiable;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Wrapper for use of esup otp api.
 */
@ThreadSafe
@NoArgsConstructor
@CustomLog
public final class DefaultEsupOtpIntegration extends AbstractInitializableComponent
        implements PrincipalSupportingComponent {

    /** API host. */
    @GuardedBy("this")
    @NonnullAfterInit
    @NotEmpty
    private String apiHost;

    /** Integration key. */
    @GuardedBy("this")
    @Nullable
    private String clientId;

    /** Secret key. */
    @GuardedBy("this")
    @Nullable
    @Getter(onMethod_ = { @Synchronized })
    private String secretKey;

    /** Users secret. */
    @GuardedBy("this")
    @NonnullAfterInit
    @NotEmpty
    @Getter(onMethod_ = { @Synchronized })
    private String usersSecret;

    /** API password. */
    @GuardedBy("this")
    @NonnullAfterInit
    @NotEmpty
    @Getter(onMethod_ = { @Synchronized })
    private String apiPassword;

    /** Issuer. */
    @GuardedBy("this")
    @NonnullAfterInit
    @NotEmpty
    @Getter(onMethod_ = { @Synchronized })
    private String issuer;

    /** The list of supported methods for otp. */
    @GuardedBy("this")
    @Nonnull
    @NonnullElements
    @Getter(onMethod_ = { @Synchronized })
    private Set<String> supportedMethods = new HashSet<>();

    /** The max send counter. */
    @GuardedBy("this")
    @Getter(onMethod_ = { @Synchronized })
    private int maxRetry;

    /** The otp code length. */
    @GuardedBy("this")
    @Getter(onMethod_ = { @Synchronized })
    private int codeLength;

    /** The supported principal subject. */
    @GuardedBy("this")
    @Nonnull
    @Getter(onMethod_ = { @Synchronized })
    private final Subject supportedPrincipals = new Subject();

    @Nonnull
    @NotEmpty
    @Synchronized
    public String getAPIHost() {
        checkComponentActive();
        assert apiHost != null;
        return apiHost;
    }

    /**
     * Set the API host to use.
     *
     * @param host
     *            API host
     */
    @Synchronized
    public void setAPIHost(@Nonnull @NotEmpty final String host) {
        checkSetterPreconditions();
        apiHost = Constraint.isNotNull(StringSupport.trimOrNull(host), "API host cannot be null or empty");
    }

    @Nullable
    @Synchronized
    public String getClientId() {
        checkComponentActive();
        return clientId;
    }

    /**
     * Set the client ID to use.
     *
     * @param id
     *            the client identifier.
     */
    @Synchronized
    public void setClientId(@Nullable final String id) {
        checkSetterPreconditions();
        clientId = Constraint.isNotNull(StringSupport.trimOrNull(id), "ClientID cannot be null or empty");
    }

    /**
     * Set the secret key to use.
     *
     * @param key
     *            secret key
     */
    @Synchronized
    public void setSecretKey(@Nullable final String key) {
        checkSetterPreconditions();
        secretKey = Constraint.isNotNull(StringSupport.trimOrNull(key), "Secret key cannot be null or empty");
    }

    /**
     * Set the users secret to use.
     *
     * @param secret
     *            secret key
     */
    @Synchronized
    public void setUsersSecret(@Nonnull @NotEmpty final String secret) {
        checkSetterPreconditions();
        usersSecret = StringSupport.trimOrNull(secret);
    }

    /**
     * Set the api password to use.
     *
     * @param password
     *            secret key
     */
    @Synchronized
    public void setApiPassword(@Nullable final String password) {
        checkSetterPreconditions();
        apiPassword = StringSupport.trimOrNull(password);
    }

    /**
     * Set the issuer to use.
     *
     * @param iss
     *            generally equal to ${idp.entityID}
     */
    @Synchronized
    public void setIssuer(@Nullable final String iss) {
        checkSetterPreconditions();
        issuer = StringSupport.trimOrNull(iss);
    }

    /**
     * Set the supportedMethods to use.
     *
     * @param methods
     *            the methods allowed
     */
    @Synchronized
    public void setSupportedMethods(@Nullable @NonnullElements final Set<String> methods) {
        checkSetterPreconditions();
        supportedMethods.clear();

        if (methods != null && !methods.isEmpty()) {
            supportedMethods = CollectionSupport.copyToSet(StringSupport.normalizeStringCollection(methods));
        }
    }

    /**
     * Set the max retry to use.
     *
     * @param maxCounter
     *            int to define how many retry can be done to recall esup-otp-api
     */
    @Synchronized
    public void setMaxRetry(final int maxCounter) {
        checkSetterPreconditions();
        maxRetry = maxCounter;
    }

    /**
     * Set the otp code length.
     *
     * @param length
     *            int to define the totp code length
     */
    @Synchronized
    public void setCodeLength(final int length) {
        checkSetterPreconditions();
        codeLength = length;
    }

    /** {@inheritDoc} */
    @Override
    public @Nonnull @Unmodifiable @NotLive <T extends Principal> Set<T> getSupportedPrincipals(
            @Nonnull final Class<T> c) {
        final Set<T> result = supportedPrincipals.getPrincipals(c);
        assert result != null;
        return result;
    }

    /**
     * Set supported non-user-specific principals that the action will include in
     * the subjects it generates, in place of any default principals from the flow.
     *
     * <p>
     * Setting to a null or empty collection will maintain the default behavior of
     * relying on the flow.
     * </p>
     *
     * @param <T>
     *            a type of principal to add, if not generic
     * @param principals
     *            supported principals to include
     */
    @Synchronized
    public <T extends Principal> void setSupportedPrincipals(
            @Nullable @NonnullElements final Collection<T> principals) {
        checkSetterPreconditions();
        supportedPrincipals.getPrincipals().clear();

        if (principals != null && !principals.isEmpty()) {
            supportedPrincipals.getPrincipals().addAll(Set.copyOf(principals));
        }
    }
}
