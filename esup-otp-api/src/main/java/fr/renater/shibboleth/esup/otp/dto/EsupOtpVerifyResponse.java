package fr.renater.shibboleth.esup.otp.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Esup otp verify dto response.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@RequiredArgsConstructor
@ToString(callSuper = true, includeFieldNames = true)
@EqualsAndHashCode(callSuper = true)
public class EsupOtpVerifyResponse extends EsupOtpResponse {

    /** Method response. */
    private String method;

}
