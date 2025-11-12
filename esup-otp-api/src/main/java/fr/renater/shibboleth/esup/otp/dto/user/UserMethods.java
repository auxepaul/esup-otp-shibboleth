package fr.renater.shibboleth.esup.otp.dto.user;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

/**
 * List of user methods.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserMethods {

    /** code required if totp, random_code, random_code_mail, bypass is active. */
    private boolean codeRequired;

    /** waiting for if push or esupnfc is active. */
    private boolean waitingFor;

    /** totp user method. */
    private UserMethod totp;

    /** webauthn user method. */
    private UserMethod webauthn;

    /** random code (totp) user method. */
    @JsonProperty("random_code")
    private UserMethod randomCode;

    /** random code (by mail) user method. */
    @JsonProperty("random_code_mail")
    private UserMethod randomCodeMail;

    /** bypass user method. */
    private UserMethod bypass;

    /** passcode_grid user method. */
    @JsonProperty("passcode_grid")
    private UserMethod passcodeGrid;

    /** push user method. */
    private UserMethod push;

    /** nfc user method. */
    private UserMethod esupnfc;

    /**
     * Get user methods by type.
     *
     * @return all user methods.
     */
    @JsonIgnore
    public Map<String, UserMethod> getAll() {
        final Map<String, UserMethod> userMethodByType = new HashMap<String, UserMethods.UserMethod>();
        userMethodByType.put("totp", totp);
        userMethodByType.put("webauthn", webauthn);
        userMethodByType.put("random_code", randomCode);
        userMethodByType.put("random_code_mail", randomCodeMail);
        userMethodByType.put("bypass", bypass);
        userMethodByType.put("passcode_grid", passcodeGrid);
        userMethodByType.put("push", push);
        userMethodByType.put("esupnfc", esupnfc);
        return userMethodByType;
    }

    /**
     * User method dto.
     */
    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class UserMethod {

        /** Boolean to get if method is active or not. */
        private boolean active;

        /** List of transports available for this method. */
        private List<String> transports;

        /** Text message sent for this method. */
        private String message;

        /** Qr code not implemented yet in esup-otp-api. */
        private String qrCode;

        /** List of codes not used yet for bypass method. Not returned with get user infos endpoint. */
        private List<Integer> codes;

        /** Number of code available with bypass method. */
        @JsonProperty("available_code")
        private int availableCode;

        /** Number of code used with bypass method. */
        @JsonProperty("used_code")
        private int usedCode;

        /** Device dto set only for push method. */
        private Device device;

    }
}
