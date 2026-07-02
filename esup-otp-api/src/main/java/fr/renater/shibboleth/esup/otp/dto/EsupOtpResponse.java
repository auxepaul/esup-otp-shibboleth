package fr.renater.shibboleth.esup.otp.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import fr.renater.shibboleth.esup.otp.config.EsupOtpMessageDeserializer;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Esup otp base response.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@RequiredArgsConstructor
@ToString
@EqualsAndHashCode
public class EsupOtpResponse {

    /**
     * Code
     */
    private String code;

    /**
     * Message
     */
    @JsonDeserialize(using = EsupOtpMessageDeserializer.class)
    private Object message;

}
