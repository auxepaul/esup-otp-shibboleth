package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import com.beust.jcommander.Parameter;

import net.shibboleth.idp.cli.AbstractIdPHomeAwareCommandLineArguments;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.PrintStream;

/**
 * Arguments for {@link EsupOtpAuthenticatorCLI}.
 */
public class EsupOtpAuthenticatorArguments extends AbstractIdPHomeAwareCommandLineArguments {

    /** Credential issuer. */
    @Parameter(names = {"-c", "--command"})
    @Nullable private String command;

    /** Credential account name. */
    @Parameter(names = "--uid")
    @Nullable private String uid;

    /** method (bypass, passcode_grid, esupnfc, push, random_code_mail, random_code, totp, webauthn). */
    @Parameter(names = "--method")
    @Nullable private String method;

    /** Chosen transport. */
    @Parameter(names = "--transport")
    @Nullable private String transport;

    /** Credential account name. */
    @Parameter(names = "--userHash")
    @Nullable private String userHash;

    /** Token code to verify. */
    @Parameter(names = "--tokencode")
    @Nullable private Integer tokenCode;

    /** The Log. */
    @Nullable private Logger log;

    /** {@inheritDoc} */
    @Nonnull public Logger getLog() {
        if (log == null) {
            log = LoggerFactory.getLogger(EsupOtpAuthenticatorArguments.class);
        }
        assert log != null;
        return log;
    }

    /** {@inheritDoc} */
    public String getCommand() {
        return command;
    }

    /** {@inheritDoc} */
    public String getMethod() {
        return method;
    }

    /** {@inheritDoc} */
    public String getTransport() {
        return transport;
    }

    /** {@inheritDoc} */
    public String getUserHash() {
        return userHash;
    }

    /**
     * Get the token account name.
     *
     * @return token account name
     */
    @Nullable @NotEmpty public String getUid() {
        return StringSupport.trimOrNull(uid);
    }

    /**
     * Get token code to verify.
     *
     * @return token code
     */
    @Nullable public Integer getTokenCode() {
        return tokenCode;
    }

    /** {@inheritDoc} */
    public void validate() throws IllegalArgumentException {
        super.validate();

        if (getOtherArgs().size() == 0) {
            throw new IllegalArgumentException("Invalid operation requested, must have one additional arguments");
        } else if (getOtherArgs().size() == 3) {
            tokenCode = Integer.valueOf(getOtherArgs().get(2));
        }
    }

    /** {@inheritDoc} */
    public void printHelp(@Nonnull final PrintStream out) {
        out.println("EsupOtpAuthenticatorCLI");
        out.println("Provides a command line interface for EsupOtpAuthenticator operations.");
        out.println();
        out.println("   EsupOtpAuthenticatorCLI [options] [uid] [tokencode]");
        out.println();
        out.println("      uid                      user identifier");
        out.println("      tokencode                token code to validate (omit when generating a new credential)");
        super.printHelp(out);
        out.println();
        out.println(String.format("  --%-20s %s", "command",
                "Specify a command to use. (all, ...)"));
        out.println(String.format("  --%-20s %s", "uid", "Specify user uid."));
        out.println(String.format("  --%-20s %s", "method",
                "Specify method. By default it's set to totp."
                + "Possible values : bypass, passcode_grid, esupnfc, push, random_code_mail, random_code, totp, webauthn"));
        out.println(String.format("  --%-20s %s", "transport", "Specify transport. By default it's set to sms."
                + "Possible values : sms, mail, push"));
        out.println(String.format("  --%-20s %s", "userHash", "Specify userHash to call api."));
        out.println(String.format("  --%-20s %s", "tokencode", "Specify token code to verify."));
        out.println();
    }

}
