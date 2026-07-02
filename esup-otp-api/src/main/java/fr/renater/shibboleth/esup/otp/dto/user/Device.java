package fr.renater.shibboleth.esup.otp.dto.user;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Device dto.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@RequiredArgsConstructor
@ToString
@EqualsAndHashCode
public class Device {

    /** platform. */
    private String platform;

    /** phone number. */
    @JsonProperty("phone_number")
    private String phoneNumber;

    /** manufacturer. */
    private String manufacturer;

    /** model. */
    private String model;

}
