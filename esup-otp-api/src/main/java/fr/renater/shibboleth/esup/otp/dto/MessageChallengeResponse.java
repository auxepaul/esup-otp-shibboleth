package fr.renater.shibboleth.esup.otp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Dto when EsupOtpResponse message is a challenge object.
 */
@Getter
@Setter
@RequiredArgsConstructor
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class MessageChallengeResponse {

    /** Line and column of the challenge with passcode_grid method. */
    private Integer[] challenge;
}
