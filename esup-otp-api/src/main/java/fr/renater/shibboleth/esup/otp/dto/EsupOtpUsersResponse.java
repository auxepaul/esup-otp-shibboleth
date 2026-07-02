package fr.renater.shibboleth.esup.otp.dto;

import java.util.List;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Esup otp users uid response.
 */
@Getter
@Setter
@ToString(callSuper = true, includeFieldNames = true, exclude = { "message" })
public class EsupOtpUsersResponse extends EsupOtpResponse {

    /** Uids */
    private List<String> uids;


}
