package fr.renater.shibboleth.idp.plugin.authn.esup.otp.mapper;

import java.util.Base64;
import java.util.List;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyWebAuthnRequest;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpWebauthnResponse;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnDto;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnPublicKeyCredential;

@Mapper
public interface WebauthnMapper {

    WebauthnMapper INSTANCE = Mappers.getMapper(WebauthnMapper.class);

    @Mapping(target = "challenge", expression = "java(base64URLStringToBuffer(webauthnResponse.getNonce()))")
    @Mapping(target = "rp", source = "rp")
    @Mapping(target = "rpId", source = "rp.id")
    @Mapping(target = "pubKeyCredParams", source = "pubKeyTypes")
    // TODO get webauthn.timeout from properties
    @Mapping(target = "timeout", expression = "java(getTimeout())")
    @Mapping(target = "attestation", constant = "none")
    @Mapping(target = "allowCredentials", expression = "java(transformAuths(webauthnResponse.getAuths()))")
    WebAuthnDto toWebAuthnDto(EsupOtpWebauthnResponse webauthnResponse);

    /**
     * Serialize {@link WebAuthnPublicKeyCredential} object to
     * {@link EsupOtpVerifyWebAuthnRequest}
     *
     * note: credID is contained in response, as response.id note: response.id and
     * response.rawId are the same when sending because rawId is an arraybuffer, and
     * toWebAuthnResponseDto converts it to a string, causing to equal id. note =>
     * 3x the same id is sent, redundant
     *
     * @param webAuthnPublicKeyCredential
     * @return
     */
    @Mapping(target = "credId", source = "id")
    @Mapping(target = "response", expression = "java(toWebAuthnResponseDto(webAuthnPublicKeyCredential))")
    EsupOtpVerifyWebAuthnRequest toEsupOtpVerifyWebAuthnRequestDto(
            WebAuthnPublicKeyCredential webAuthnPublicKeyCredential);

    @Mapping(target = "rawId", expression = "java(bufferToBase64URLString(webAuthnPublicKeyCredential.getRawId()))")
    @Mapping(target = "authenticatorAttachment", expression = "java(toAuthenticatorAttachment(webAuthnPublicKeyCredential.getAuthenticatorAttachment()))")
    EsupOtpVerifyWebAuthnRequest.WebAuthnResponse toWebAuthnResponseDto(
            WebAuthnPublicKeyCredential webAuthnPublicKeyCredential);

    @Mapping(target = "authenticatorData", expression = "java(bufferToBase64URLString(webAuthnAuthenticatorAssertionResponse.getAuthenticatorData()))")
    @Mapping(target = "clientDataJson", expression = "java(bufferToBase64URLString(webAuthnAuthenticatorAssertionResponse.getClientDataJson()))")
    @Mapping(target = "signature", expression = "java(bufferToBase64URLString(webAuthnAuthenticatorAssertionResponse.getSignature()))")
    @Mapping(target = "userHandle", expression = "java(bufferToBase64URLString(webAuthnAuthenticatorAssertionResponse.getUserHandle()))")
    EsupOtpVerifyWebAuthnRequest.WebAuthnResponse.ResponseData toWebAuthnResponseDataDto(
            WebAuthnPublicKeyCredential.WebAuthnAuthenticatorAssertionResponse webAuthnAuthenticatorAssertionResponse);

    /**
     * Get byte array to Base64 String.
     * 
     * @param buffer
     *            byte array.
     * @return base64.
     */
    default String bufferToBase64URLString(byte[] buffer) {
        if (buffer == null || buffer.length == 0) {
            return null; // Retourner null si le buffer est null ou vide
        }

        // Encoder en Base64
        String base64String = Base64.getEncoder().encodeToString(buffer);

        // Convertir Base64 en Base64URL
        return base64String.replace('+', '-') // Remplace '+' par '-'
                .replace('/', '_') // Remplace '/' par '_'
                .replace("=", ""); // Supprime les '=' de padding

    }

    /**
     * Convert String to byte array.
     * 
     * @param value
     * @return
     */
    default byte[] base64URLStringToBuffer(String value) {
        // Convertir Base64URL en Base64
        String base64 = value.replace('-', '+') // Convertir '-' en '+'
                .replace('_', '/'); // Convertir '_' en '/'

        // Ajouter le padding nécessaire pour obtenir une longueur multiple de 4
        int paddingLength = (4 - (base64.length() % 4)) % 4;
        for (int i = 0; i < paddingLength; i++) {
            base64 += "=";
        }

        // Décoder la chaîne Base64 en tableau de bytes
        return Base64.getDecoder().decode(base64);
    }

    default List<WebAuthnDto.AllowCredentialDto> transformAuths(List<EsupOtpWebauthnResponse.EsupOtpAuth> auths) {
        return auths.stream()
                .map(auth -> new WebAuthnDto.AllowCredentialDto(base64URLStringToBuffer(auth.getCredentialId()),
                        "public-key"))
                .toList();
    }

    default int getTimeout() {
        return 3 * 60000;
    }

    default EsupOtpVerifyWebAuthnRequest.WebAuthnResponse.AuthenticatorAttachment toAuthenticatorAttachment(
            String value) {
        return EsupOtpVerifyWebAuthnRequest.WebAuthnResponse.AuthenticatorAttachment.fromString(value);
    }
}
