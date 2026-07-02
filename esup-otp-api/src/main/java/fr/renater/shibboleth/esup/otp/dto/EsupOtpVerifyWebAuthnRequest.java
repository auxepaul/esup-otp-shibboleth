package fr.renater.shibboleth.esup.otp.dto;

import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Esup otp verify dto request for webauthn transport.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@RequiredArgsConstructor
@ToString
@EqualsAndHashCode
public class EsupOtpVerifyWebAuthnRequest {

    /** Webauthn response. */
    private WebAuthnResponse response;

    /** Credential id. */
    @JsonProperty("credID")
    private String credId;

    /**
     * Nested object of webauthn response.
     */
    @Getter
    @Setter
    @RequiredArgsConstructor
    @ToString
    @EqualsAndHashCode
    public static class WebAuthnResponse {

        /**
         * The raw Credential ID of this credential, corresponding to the
         * <code>rawId</code> attribute in the WebAuthn API.
         */
        private String id;

        /** The type value is the string "public-key". */
        private String type;

        /** Webauthn rawId. */
        private String rawId;

        /**
         * The authenticator's response to the client’s request to either create a
         * public key credential, or generate an authentication assertion.
         *
         * <p>
         * The {@link WebAuthnResponse} was created in response to
         * <code>navigator.credentials.get()</code>, and this attribute’s value will be
         * an {@link ResponseData}.
         * </p>
         */
        private ResponseData response;

        /**
         * The authenticator attachment requirement (cross-platform or platform).
         * {@code null} would represent either possibility.
         */
        private AuthenticatorAttachment authenticatorAttachment;

        /**
         * Represents an authenticator's response to a client’s request for generation
         * of a new authentication assertion given the WebAuthn Relying Party's
         * {@linkplain EsupOtpWebauthnResponse#getNonce()} challenge} and OPTIONAL
         * {@linkplain EsupOtpWebauthnResponse#getAuths()} list of credentials} it is
         * aware of. This response contains a cryptographic {@linkplain #signature}
         * proving possession of the credential private key, and optionally evidence of
         * user consent to a specific transaction.
         *
         * @see <a href=
         *      "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticatorassertionresponse">§5.2.2.
         *      Web Authentication Assertion (interface AuthenticatorAssertionResponse)
         *      </a>
         */
        @Getter
        @Setter
        @RequiredArgsConstructor
        @ToString
        @EqualsAndHashCode
        public static class ResponseData {

            /** The authenticator data returned by the authenticator. */
            private String authenticatorData;

            /**
             * The JSON-serialized client data passed to the authenticator by the client in
             * the call to either navigator.credentials.create() or
             * navigator.credentials.get(). The exact JSON serialization MUST be preserved,
             * as the hash of the serialized client data has been computed.
             */
            @JsonProperty("clientDataJSON")
            private String clientDataJson;

            /**
             * The raw signature returned from the authenticator. See <a href=
             * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3
             * The authenticatorGetAssertion Operation</a>.
             */
            private String signature;

            /**
             * The user handle returned from the authenticator, or empty if the
             * authenticator did not return a user handle. See <a href=
             * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3
             * The authenticatorGetAssertion Operation</a>.
             */
            private String userHandle;
        }

        /**
         * This enumeration’s values describe authenticators' <a href=
         * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-attachment-modality">attachment
         * modalities</a>. Relying Parties use this for two purposes:
         *
         * <ul>
         * <li>to express a preferred authenticator attachment modality when calling
         * <code>
         *       navigator.credentials.create()</code> to create a credential, and
         * <li>to inform the client of the Relying Party's best belief about how to
         * locate the managing authenticators of the credentials listed in
         * {@link EsupOtpWebauthnResponse#getAuths()} when calling <code>
         *       navigator.credentials.get()</code>.
         * </ul>
         *
         * @see <a href=
         *      "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-authenticatorattachment">§5.4.5.
         *      Authenticator Attachment Enumeration (enum AuthenticatorAttachment) </a>
         */
        @AllArgsConstructor
        public enum AuthenticatorAttachment {
            /**
             * Indicates <a href=
             * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#cross-platform-attachment">cross-platform
             * attachment</a>.
             *
             * <p>
             * Authenticators of this class are removable from, and can "roam" among, client
             * platforms.
             */
            CROSS_PLATFORM("cross-platform"),

            /**
             * Indicates <a href=
             * "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#platform-attachment">platform
             * attachment</a>.
             *
             * <p>
             * Usually, authenticators of this class are not removable from the platform.
             */
            PLATFORM("platform");

            /**
             * value as String.
             */
            private final String value;

            /**
             * Get AuthenticatorAttachment enum from String value.
             *
             * <p>
             * Same function as {@link Enum#valueOf(Class, String)} but don't throw NPE.
             * </p>
             *
             * @param value
             *            cross-platform or platform
             * @return an AuthenticatorAttachment enum
             */
            @JsonCreator
            public static AuthenticatorAttachment fromString(final String value) {
                return value != null ? Stream.of(values()).filter(v -> v.value.equals(value)).findAny().orElse(null)
                        : null;
            }
        }
    }
}
