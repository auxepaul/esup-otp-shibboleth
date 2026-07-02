package fr.renater.shibboleth.esup.otp.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Dto when EsupOtpResponse message is an object.
 */
@Getter
@Setter
@RequiredArgsConstructor
@ToString
public class MessageStatusResponse {

    /** message id. */
    private Integer id;

    /** message status. */
    private String status;
}
