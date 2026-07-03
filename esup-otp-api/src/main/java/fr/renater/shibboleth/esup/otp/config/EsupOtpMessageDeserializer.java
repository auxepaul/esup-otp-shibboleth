package fr.renater.shibboleth.esup.otp.config;

import java.io.IOException;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.renater.shibboleth.esup.otp.dto.MessageChallengeResponse;
import fr.renater.shibboleth.esup.otp.dto.MessageStatusResponse;
import lombok.CustomLog;

/**
 * EsupOtp custom deserializer.
 */
@CustomLog
public class EsupOtpMessageDeserializer extends JsonDeserializer<Object> {

    @Override
    public Object deserialize(final JsonParser p, final DeserializationContext ctxt)
            throws IOException, JacksonException {
        if (p.currentToken() == JsonToken.VALUE_STRING) {
            log.debug("Message is a string: {}", p.toString());
            return p.readValueAs(String.class);
        } else if (p.currentToken() == JsonToken.START_OBJECT) {
            ObjectMapper mapper = (ObjectMapper) p.getCodec();
            JsonNode node = mapper.readTree(p);
            if (node.has("status")) {
                log.debug("Message has a status: {}", node.toString());
                return p.readValueAs(MessageStatusResponse.class);
            } else if (node.has("challenge") && node.path("challenge").isArray()) {
                log.debug("Message has a challenge: {}", node.toString());
                return mapper.treeToValue(node, MessageChallengeResponse.class);
            } else {
                throw JsonMappingException.from(p, "Unable to parse EsupOtpMessage Object response");
            }
        } else {
            throw JsonMappingException.from(p, "Unable to parse EsupOtpMessage response");
        }
    }
}
