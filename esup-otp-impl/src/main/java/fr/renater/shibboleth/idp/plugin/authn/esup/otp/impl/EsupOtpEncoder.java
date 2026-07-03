package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.TimeZone;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnDto;
import lombok.CustomLog;
import lombok.NoArgsConstructor;
import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * An Custom encoder for esup otp plugin.
 */
@NoArgsConstructor
@ThreadSafe
@CustomLog
public final class EsupOtpEncoder {

    @NotEmpty
    private String usersSecret;

    /**
     * Constructor
     * 
     * @param secret
     */
    public EsupOtpEncoder(@Nonnull @NotEmpty @ParameterName(name = "usersSecret") String secret) {
        this.usersSecret = StringSupport.trimOrNull(secret);
    }

    public void setUsersSecret(@Nonnull @NotEmpty final String secret) {
        usersSecret = StringSupport.trimOrNull(secret);
    }

    public static ObjectMapper getWebAuthnObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_ABSENT);
        objectMapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        objectMapper.registerModule(new JavaTimeModule());

        return objectMapper;
    }

    /**
     * Serialize the PublicKeyCredentialRequestOptions request into a JSON string.
     *
     * @param options
     *            the options to serialize
     *
     * @return the JSON serialized PublicKeyCredentialRequestOptions, or an empty
     *         string if there is an error converting the string.
     */
    public static String serializePublicKeyCredentialRequestOptionsAsJSON(@Nullable final WebAuthnDto options) {
        log.debug("Get options : {}", options);
        if (options != null) {
            try {
                ObjectMapper objectMapper = getWebAuthnObjectMapper();
                ObjectNode result = objectMapper.createObjectNode();
                result.set("publicKey", objectMapper.valueToTree(options));
                return objectMapper.writeValueAsString(result);
            } catch (final JsonProcessingException e) {
                log.debug("Unable to serialize PublicKeyCredentialOptions", e);
            }
        }
        return "";
    }

    /**
     * Compute user hash for request need it.
     * 
     * @param uid
     * @return user hash
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public String getUserHash(final String uid) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        log.debug("Get user hash start");
        if (usersSecret == null) {
            log.warn("Users secret not configured");
            return null;
        }
        final MessageDigest md5Md = MessageDigest.getInstance("MD5");
        final String md5 = bytesToHex(md5Md.digest(usersSecret.getBytes())).toLowerCase();
        final String salt = md5 + getSalt(uid);
        final MessageDigest sha256Md = MessageDigest.getInstance("SHA-256");
        final String userHash = bytesToHex(sha256Md.digest(salt.getBytes())).toLowerCase();
        log.debug("Get user hash for {} = {}", uid, userHash);
        return userHash;
    }

    /**
     * Convert bytes array to hexadecimal string.
     * 
     * @param bytes
     * @return hexadecimal string.
     */
    private static String bytesToHex(final byte[] bytes) {
        final StringBuilder hexString = new StringBuilder();
        for (final byte b : bytes) {
            final String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Get salt for uid.
     * 
     * @param uid
     * @return salt.
     */
    public static String getSalt(final String uid) {
        final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        final int day = calendar.get(Calendar.DAY_OF_MONTH);
        final int hour = calendar.get(Calendar.HOUR_OF_DAY);
        final String salt = uid + day + hour;
        return salt;
    }
}
