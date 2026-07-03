package fr.renater.shibboleth.idp.plugin.authn.esup.otp.context;

import javax.annotation.Nullable;

import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnDto;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnPublicKeyCredential;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

import java.util.*;

/**
 * Context class for state of a Esup otp validation.
 */
@Getter
@Setter
@NoArgsConstructor
public class EsupOtpContext extends BaseContext {

    /** The subject identifier with respect to the token "back-end". */
    @Nullable
    @NotEmpty
    private String username;

    /** The choices configured by the user. */
    @Nullable
    private Set<String> enabledChoices = new HashSet<>();

    /** The possible transports configured by the user. */
    @Nullable
    private Map<String, String> configuredTransports = new HashMap<>();

    /** The method chosen. */
    @Nullable
    private String methodChoice;

    /** The counter of send message done. */
    private int sendCounter;

    /** The webauthn dto. */
    @Nullable
    private WebAuthnDto webauthnCredentialRequestOptions;

    /**
     * A public key credential with assertion response that is the result of
     * authentication.
     */
    @Nullable
    private WebAuthnPublicKeyCredential publicKeyCredentialAssertionResponse;

    /** The token code supplied. */
    @Nullable
    private Integer tokenCode;

    /** The passcode_grid challenge supplied. */
    @Nullable
    private PasscodeGridChallenge passcodeGridChallenge;

    public void setPasscodeGridChallenge(@NonNull Integer[] challenge)
    {
        if(challenge != null && challenge.length == 2) {
           passcodeGridChallenge = new PasscodeGridChallenge(challenge[0],challenge[1]);
        } else
        {
            // TODO générer une exception
        }
    }
    
    @Getter
    @ToString
    public class PasscodeGridChallenge {
        private Character line;
        
        private Integer column;
        
        
        public PasscodeGridChallenge(int l, int c) {
            line = (char) ('A' + l);
            column = c + 1;
        }
    }

}
