package fr.renater.shibboleth.idp.plugin.authn.esup.otp.util;

import java.util.List;

public class EsupOtpUtils {

    public static final String BYPASS_METHOD = "bypass";

    public static final String PASSCODE_GRID_METHOD = "passcode_grid";

    public static final String TOTP_METHOD = "totp";

    public static final String WEBAUTHN_METHOD = "webauthn";

    public static final String PUSH_METHOD = "push";

    public static final List<String> SUPPORTED_METHODS_WITHOUT_TRANSPORT = List.of(BYPASS_METHOD, PASSCODE_GRID_METHOD, WEBAUTHN_METHOD, TOTP_METHOD, PUSH_METHOD);

}
