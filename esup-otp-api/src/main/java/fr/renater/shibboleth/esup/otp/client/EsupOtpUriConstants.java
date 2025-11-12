package fr.renater.shibboleth.esup.otp.client;

/**
 * Esup otp api constants.
 */
public final class EsupOtpUriConstants {

    /**
     * Public uris.
     */
    public final class Public {

        /**
         * GET request to retrieve user information using a unique identifier and a hash for verification.
         *
         * Endpoint: /users/{uid}/{hash}
         *
         * @param uid The unique identifier of the user.
         * @param hash A hash used for verification or security purposes.
         */
        public static final String GET_USER_INFOS = "/users/{uid}/{hash}";

        /**
         * POST request to send a message using a specific method and transport associated with a user.
         *
         * Endpoint: /users/{uid}/methods/{method}/transports/{transport}/{hash}
         *
         * @param uid The unique identifier of the user.
         * @param method The method being used for sending the message.
         * @param transport The transport mechanism used for delivering the message.
         * @param hash A hash used for verification or security purposes.
         */
        public static final String POST_MESSAGE = "/users/{uid}/methods/{method}/transports/{transport}/{hash}";

        /**
         * POST request to generate a WebAuthn secret for the specified user with a security hash.
         *
         * Endpoint: /users/{uid}/methods/webauthn/secret/{hash}
         *
         * @param uid The unique identifier of the user.
         * @param hash A hash used for verification or security purposes.
         */
        public static final String POST_GENERATE_WEBAUTHN = "/users/{uid}/methods/webauthn/secret/{hash}";

        /**
         * POST request to verify WebAuthn login for the specified user with a security hash.
         *
         * Endpoint: /users/{uid}/webauthn/login/{hash}
         *
         * @param uid The unique identifier of the user.
         * @param hash A hash used for verification or security purposes.
         */
        public static final String POST_VERIFY_WEBAUTHN = "/users/{uid}/webauthn/login/{hash}";

        /**
         * Constructor.
         *
         */
        private Public() {

        }

    }

    /**
     * Protected uris.
     */
    public final class Protected {

        /**
         * GET request to retrieve detailed information of a specific user.
         *
         * Endpoint: /protected/users/{uid}
         *
         * @param uid The unique identifier of the user whose information is being requested.
         */
        public static final String GET_USER_INFOS = "/protected/users/{uid}";

        /**
         * GET request to test a specific transport for a user.
         *
         * Endpoint: /protected/users/{uid}/transports/{transport}/test
         *
         * @param uid The unique identifier of the user.
         * @param transport The specific transport method being tested.
         */
        public static final String GET_TRANSPORT_TEST = "/protected/users/{uid}/transports/{transport}/test";

        /**
         * PUT request to activate a specific method for a user.
         *
         * Endpoint: /protected/users/{uid}/methods/{method}/activate
         *
         * @param uid The unique identifier of the user.
         * @param method The method to be activated.
         */
        public static final String PUT_ACTIVATE = "/protected/users/{uid}/methods/{method}/activate";

        /**
         * PUT request to deactivate a specific method for a user.
         *
         * Endpoint: /protected/users/{uid}/methods/{method}/deactivate
         *
         * @param uid The unique identifier of the user.
         * @param method The method to be deactivated.
         */
        public static final String PUT_DEACTIVATE = "/protected/users/{uid}/methods/{method}/deactivate";

        /**
         * POST request to confirm the activation of a method using an activation code.
         *
         * Endpoint: /protected/users/{uid}/methods/{method}/activate/{activation_code}
         *
         * @param uid The unique identifier of the user.
         * @param method The method being activated.
         * @param activation_code The code required to confirm activation.
         */
        public static final String POST_CONFIRM_ACTIVATE = "/protected/users/{uid}/methods/{method}/activate/{activation_code}";

        /**
         * PUT request to update a specific transport method for a user.
         *
         * Endpoint: /protected/users/{uid}/transports/{transport}/{new_transport}
         *
         * @param uid The unique identifier of the user.
         * @param transport The current transport method.
         * @param new_transport The new transport method to be set.
         */
        public static final String PUT_UPDATE_TRANSPORT = "/protected/users/{uid}/transports/{transport}/{new_transport}";

        /**
         * GET request to test a newly updated transport for a user.
         *
         * Endpoint: /protected/users/{uid}/transports/{transport}/{new_transport}/test
         *
         * @param uid The unique identifier of the user.
         * @param transport The current transport method.
         * @param new_transport The new transport method being tested.
         */
        public static final String GET_NEW_TRANSPORT_TEST = "/protected/users/{uid}/transports/{transport}/{new_transport}/test";

        /**
         * POST request to set a secret for a specific method for a user.
         *
         * Endpoint: /protected/users/{uid}/methods/{method}/secret
         *
         * @param uid The unique identifier of the user.
         * @param method The method for which the secret is being set.
         */
        public static final String POST_SECRET = "/protected/users/{uid}/methods/{method}/secret";

        /**
         * POST request to verify the user with an OTP and API password.
         *
         * Endpoint: /protected/users/{uid}/{otp}/{api_password}
         *
         * @param uid The unique identifier of the user.
         * @param otp The one-time password for verification.
         * @param api_password The API password for additional security.
         */
        public static final String POST_VERIFY = "/protected/users/{uid}/{otp}";

        /**
         * DELETE request to remove a specific transport method for a user.
         *
         * Endpoint: /protected/users/{uid}/transports/{transport}
         *
         * @param uid The unique identifier of the user.
         * @param transport The transport method to be deleted.
         */
        public static final String DELETE_TRANSPORT = "/protected/users/{uid}/transports/{transport}";

        /**
         * Constructor.
         *
         */
        private Protected() {

        }

    }

    /**
     * Admin uris.
     */
    public final class Admin {

        /**
         * GET request to retrieve the list of all users.
         *
         * Endpoint: /admin/users
         */
        public static final String GET_USERS = "/admin/users";

        /**
         * GET request to retrieve details of a specific user.
         *
         * Endpoint: /admin/users/{uid}
         *
         * @param uid The unique identifier of the user.
         */
        public static final String GET_USER = "/admin/users/{uid}";

        /**
         * GET request to retrieve all methods associated with a specific user.
         *
         * Endpoint: /admin/users/{uid}/methods
         *
         * @param uid The unique identifier of the user.
         */
        public static final String GET_METHODS = "/admin/users/{uid}/methods";

        /**
         * PUT request to activate a specific transport for a method.
         *
         * Endpoint: /admin/methods/{method}/transports/{transport}/activate
         *
         * @param method The method associated with the transport.
         * @param transport The transport to be activated.
         */
        public static final String PUT_ACTIVATE_TRANSPORT = "/admin/methods/{method}/transports/{transport}/activate";

        /**
         * PUT request to deactivate a specific transport for a method.
         *
         * Endpoint: /admin/methods/{method}/transports/{transport}/deactivate
         *
         * @param method The method associated with the transport.
         * @param transport The transport to be deactivated.
         */
        public static final String PUT_DEACTIVATE_TRANSPORT = "/admin/methods/{method}/transports/{transport}/deactivate";

        /**
         * PUT request to activate a specific method.
         *
         * Endpoint: /admin/methods/{method}/activate
         *
         * @param method The method to be activated.
         */
        public static final String PUT_ACTIVATE = "/admin/methods/{method}/activate";

        /**
         * PUT request to deactivate a specific method.
         *
         * Endpoint: /admin/methods/{method}/deactivate
         *
         * @param method The method to be deactivated.
         */
        public static final String PUT_DEACTIVATE = "/admin/methods/{method}/deactivate";

        /**
         * DELETE request to remove the secret associated with a specific method for a user.
         *
         * Endpoint: /admin/users/{uid}/methods/{method}/secret
         *
         * @param uid The unique identifier of the user.
         * @param method The method for which the secret is being removed.
         */
        public static final String DELETE_SECRET = "/admin/users/{uid}/methods/{method}/secret";

        /**
         * Constructor.
         *
         */
        private Admin() {

        }
    }

    private EsupOtpUriConstants() {

    }

}
