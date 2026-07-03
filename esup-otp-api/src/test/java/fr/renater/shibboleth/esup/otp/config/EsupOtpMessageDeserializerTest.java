package fr.renater.shibboleth.esup.otp.config;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpResponse;
import fr.renater.shibboleth.esup.otp.dto.EsupOtpPasscodeGridResponse;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;

public class EsupOtpMessageDeserializerTest {

    @Test
    public final void deserializeMessageString() throws JsonParseException, JsonMappingException, IOException {
        final String json = "{\n" + "    \"code\": \"Ok\",\n" + "    \"message\": \"message\"" + "}";

        final EsupOtpResponse readValue = new ObjectMapper().readValue(json, EsupOtpResponse.class);
        Assert.assertNotNull(readValue);
    }

    @Test
    public final void deserializeMessageObject() throws JsonParseException, JsonMappingException, IOException {
        final String json = """
                {
                    "code": "Ok",
                    "message": {
                        "id": 715,
                        "status": "OK"
                    }
                }\
                """;

        final EsupOtpResponse readValue = new ObjectMapper().readValue(json, EsupOtpResponse.class);
        Assert.assertNotNull(readValue);
    }

    @Test
    public final void deserializeMessageChallenge() throws JsonParseException, JsonMappingException, IOException {
        final String json = """
                {
                    "code": "Ok",
                    "message": {
                        "challenge": [2,4]
                    }
                }\
                """;

        final EsupOtpPasscodeGridResponse readValue = new ObjectMapper().readValue(json,
                EsupOtpPasscodeGridResponse.class);
        Assert.assertNotNull(readValue);
    }

    @Test
    public final void deserializeMessageArray_exception() throws JsonParseException, JsonMappingException, IOException {
        final String json = """
                {
                    "code": "Ok",
                    "message": [{
                        "id": 715,
                        "status": "OK"
                    }]
                }\
                """;

        Assert.assertThrows(JsonMappingException.class,
                () -> new ObjectMapper().readValue(json, EsupOtpResponse.class));
    }

}
