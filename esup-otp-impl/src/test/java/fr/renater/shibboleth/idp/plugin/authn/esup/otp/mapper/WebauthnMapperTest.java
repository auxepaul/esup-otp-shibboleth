package fr.renater.shibboleth.idp.plugin.authn.esup.otp.mapper;

import static org.testng.Assert.assertNotNull;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import fr.renater.shibboleth.esup.otp.dto.EsupOtpVerifyWebAuthnRequest;
import fr.renater.shibboleth.idp.plugin.authn.esup.otp.dto.WebAuthnPublicKeyCredential;

public class WebauthnMapperTest {

    protected ObjectMapper jsonMapper;

    @BeforeMethod
    public void setUp() {
        jsonMapper = JsonMapper.builder().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                .serializationInclusion(JsonInclude.Include.NON_ABSENT)
                .defaultBase64Variant(Base64Variants.MODIFIED_FOR_URL).addModule(new JavaTimeModule()).build();
    }

    @Test
    public void toEsupOtpVerifyWebAuthnRequestDto() throws JsonProcessingException {
        final String assertionResponseJson = "{\"id\":\"Dt0aswnRG8cw5rSNbZE_1sdu8b5YLheti_YUujlC5Vo\",\"response\":{\"authenticatorData\":\"S7wmxUIOh13coAzoaY4w9wC3y0Bm_MgckM-PKf_tIikFAAAAAQ\",\"signature\":\"MEYCIQCcxqY-43wMWlVztDm7SDgq91_Yu7esLE9Ht24Htp3n4gIhAOng7EGatVtT0zVo0IVoNTmqJYSQEYMrl44t8G0cgbN2\",\"userHandle\":\"dGhpc2lzYWNoYWxsZW5nZQ\",\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImNoYWxsZW5nZSI6ImRHaHBjMmx6QmFOb1lXeHNaVzVuWlE9PSIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ\"},\"clientExtensionResults\":{\"extensionIds\":[]},\"type\":\"public-key\",\"rawId\":\"Dt0aswnRG8cw5rSNbZE_1sdu8b5YLheti_YUujlC5Vo\"}";

        final WebAuthnPublicKeyCredential webAuthnPublicKeyCredential = jsonMapper.readValue(assertionResponseJson,
                WebAuthnPublicKeyCredential.class);

        EsupOtpVerifyWebAuthnRequest request = WebauthnMapper.INSTANCE
                .toEsupOtpVerifyWebAuthnRequestDto(webAuthnPublicKeyCredential);

        assertNotNull(request);
        Assert.assertNotNull(request.getResponse());
        Assert.assertEquals(request.getResponse().getId(), request.getResponse().getRawId());
        Assert.assertNotNull(request.getResponse().getResponse());
        EsupOtpVerifyWebAuthnRequest.WebAuthnResponse.ResponseData responseData = request.getResponse().getResponse();
        Assert.assertEquals(responseData.getAuthenticatorData(), WebauthnMapper.INSTANCE
                .bufferToBase64URLString(webAuthnPublicKeyCredential.getResponse().getAuthenticatorData()));
    }
}
