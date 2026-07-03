package fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@RequiredArgsConstructor
@ToString
@EqualsAndHashCode
public class WebAuthnPublicKeyCredential {

    private String id;

    private String type;

    private byte[] rawId;

    private ClientAssertionExtensionOutputs clientExtensionResults;

    private WebAuthnAuthenticatorAssertionResponse response;

    private String authenticatorAttachment;

    @Getter
    @Setter
    @RequiredArgsConstructor
    @ToString
    @EqualsAndHashCode
    public static class WebAuthnAuthenticatorAssertionResponse {

        private byte[] authenticatorData;

        @JsonProperty("clientDataJSON")
        private byte[] clientDataJson;

        private byte[] signature;

        private byte[] userHandle;
    }

    @Getter
    @Setter
    @RequiredArgsConstructor
    @ToString
    @EqualsAndHashCode
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ClientAssertionExtensionOutputs {

        private boolean appid;

        private LargeBlobAuthenticationOutput largeBlob;

        @Getter
        @Setter
        @RequiredArgsConstructor
        @ToString
        @EqualsAndHashCode
        public static class LargeBlobAuthenticationOutput {

            private byte[] blob;

            private Boolean written;
        }
    }
}
