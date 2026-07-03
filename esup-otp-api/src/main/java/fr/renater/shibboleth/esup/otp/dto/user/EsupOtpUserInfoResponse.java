package fr.renater.shibboleth.esup.otp.dto.user;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

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
public class EsupOtpUserInfoResponse extends EsupOtpResponse {

    /** user description. */
    private User user;

    /**
     * User dto for esup-otp-api response.
     */
    @Getter
    @Setter
    @RequiredArgsConstructor
    @ToString
    @EqualsAndHashCode
    public static class User {

        /** User method registered (active or not). */
        private UserMethods methods;

        /** Transport registered by user. */
        private Transports transports;

        /** last send message dto by user. */
        @JsonProperty("last_send_message")
        private LastSendMessage lastSendMessage;

        /**
         * Transport dto, contains mail, sms, push value registered by user.
         */
        @Getter
        @Setter
        @RequiredArgsConstructor
        @ToString
        @EqualsAndHashCode
        public static class Transports {

            /** mail value. */
            private String mail;

            /** sms value. */
            private String sms;

            /** push value. */
            private String push;

            /**
             * Get transports by type.
             *
             * @return all transports values.
             */
            @JsonIgnore
            public Map<String, String> getAll() {
                final Map<String, String> transportByType = new HashMap<>();
                transportByType.put("mail", mail);
                transportByType.put("sms", sms);
                transportByType.put("push", push);
                return transportByType;
            }

        }

        /**
         * Last send message dto for user.
         */
        @Getter
        @Setter
        @RequiredArgsConstructor
        @ToString
        @EqualsAndHashCode
        public static class LastSendMessage {

            /** last method used. */
            private String method;

            /** time of last method used. */
            private Instant time;

            /** boolean auto if send message request contain auto. */
            private boolean auto;

            /** verified boolean. */
            private boolean verified;
        }
    }
}
