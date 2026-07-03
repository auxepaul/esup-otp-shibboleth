package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import java.io.PrintStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;

import com.beust.jcommander.Parameter;

import lombok.CustomLog;
import net.shibboleth.idp.cli.AbstractIdPHomeAwareCommandLineArguments;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * Arguments for {@link EsupOtpAuthenticatorCLI}.
 */
@CustomLog
public class EsupOtpAuthenticatorArguments extends AbstractIdPHomeAwareCommandLineArguments {

    /** Credential issuer. */
    @Parameter(names = { "-c", "--command" })
    @Nullable
    private String command;

    /** Credential account name. */
    @Parameter(names = "--uid")
    @Nullable
    private String uid;

    /**
     * method (bypass, passcode_grid, esupnfc, push, random_code_mail, random_code,
     * totp, webauthn).
     */
    @Parameter(names = "--method")
    @Nullable
    private String method;

    /** Chosen transport. */
    @Parameter(names = "--transport")
    @Nullable
    private String transport;

    /** Credential account name. */
    @Parameter(names = "--userHash")
    @Nullable
    private String userHash;

    /** Token code to verify. */
    @Parameter(names = "--tokencode")
    @Nullable
    private Integer tokenCode;

    /** {@inheritDoc} */
    @Nonnull
    public Logger getLog() {
        return log;
    }

    /**
     * {@inheritDoc}
     * 
     * @return
     */
    public String getCommand() {
        return command;
    }

    /**
     * {@inheritDoc}
     * 
     * @return
     */
    public String getMethod() {
        return method;
    }

    /**
     * {@inheritDoc}
     * 
     * @return
     */
    public String getTransport() {
        return transport;
    }

    /**
     * {@inheritDoc}
     * 
     * @return
     */
    public String getUserHash() {
        return userHash;
    }

    /**
     * Get the token account name.
     *
     * @return token account name
     */
    @Nullable
    @NotEmpty
    public String getUid() {
        return StringSupport.trimOrNull(uid);
    }

    /**
     * Get token code to verify.
     *
     * @return token code
     */
    @Nullable
    public Integer getTokenCode() {
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
        out.println(String.format("  --%-20s %s", "command", "Specify a command to use. (all, ...)"));
        out.println(String.format("  --%-20s %s", "uid", "Specify user uid."));
        out.println(String.format("  --%-20s %s", "method", "Specify method. By default it's set to totp."
                + "Possible values : bypass, passcode_grid, esupnfc, push, random_code_mail, random_code, totp, webauthn"));
        out.println(String.format("  --%-20s %s", "transport",
                "Specify transport. By default it's set to sms." + "Possible values : sms, mail, push"));
        out.println(String.format("  --%-20s %s", "userHash", "Specify userHash to call api."));
        out.println(String.format("  --%-20s %s", "tokencode", "Specify token code to verify."));
        out.println();
    }

}
