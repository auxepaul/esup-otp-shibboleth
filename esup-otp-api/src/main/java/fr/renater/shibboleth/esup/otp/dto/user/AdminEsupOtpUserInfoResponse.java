package fr.renater.shibboleth.esup.otp.dto.user;

import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Esup otp user response.
 */
@Getter
@Setter
@RequiredArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = true)
public class AdminEsupOtpUserInfoResponse extends EsupOtpResponse {

    /** user description. */
    private UserMethods user;
}
