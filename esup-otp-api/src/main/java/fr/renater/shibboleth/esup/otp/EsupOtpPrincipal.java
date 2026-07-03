package fr.renater.shibboleth.esup.otp;

import java.util.StringJoiner;

import javax.annotation.Nonnull;

import org.springframework.javapoet.ClassName;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/** Principal based on a EsupOtp authentication. */
public class EsupOtpPrincipal implements CloneablePrincipal {

    /** The username. */
    @Nonnull
    @NotEmpty
    private String username;

    /**
     *
     * Constructor.
     *
     * @param name
     *            the username
     */
    public EsupOtpPrincipal(@Nonnull @NotEmpty @ParameterName(name = "name") final String name) {
        username = Constraint.isNotNull(StringSupport.trimOrNull(name), "Username cannot be null or empty");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NotEmpty
    public String getName() {
        return username;
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return username.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(final Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof final EsupOtpPrincipal otherPrincipal) {
            return username.equals(otherPrincipal.getName());
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return new StringJoiner(", ", ClassName.class.getSimpleName() + "[", "]").add("username=" + username)
                .toString();
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public EsupOtpPrincipal clone() throws CloneNotSupportedException {
        final EsupOtpPrincipal copy = (EsupOtpPrincipal) super.clone();
        copy.username = username;
        return copy;
    }
}
