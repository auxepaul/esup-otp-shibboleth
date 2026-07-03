package fr.renater.shibboleth.esup.otp.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import fr.renater.shibboleth.esup.otp.config.EsupOtpMessageDeserializer;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

/**
 * Esup otp Passcode Grid response dto returned by the API.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
public class EsupOtpPasscodeGridResponse extends EsupOtpResponse {

    /**
     * Message Challenge Response.
     */
    @JsonDeserialize(using = EsupOtpMessageDeserializer.class)
    private MessageChallengeResponse message;

}
