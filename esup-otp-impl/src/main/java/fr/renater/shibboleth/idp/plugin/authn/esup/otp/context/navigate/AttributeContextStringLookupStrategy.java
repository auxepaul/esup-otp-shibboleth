package fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.navigate;

import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

import org.opensaml.profile.context.ProfileRequestContext;

import lombok.CustomLog;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;

/**
 * An {@link AbstractAttributeContextUserIdentityStrategy} that pulls out an
 * {@link StringAttributeValue} from the attribute context. Will return
 * {@code null} if the attribute can not be found, or if there is more than one attribute value.
 */
@CustomLog
@ThreadSafe
public class AttributeContextStringLookupStrategy extends AbstractAttributeContextUserIdentityStrategy<String> {
    /** {@inheritDoc} */
    @Override
    @Nullable
    public String apply(final ProfileRequestContext profileRequestContext) {
        if (profileRequestContext == null) {
            return null;
        }

        final IdPAttribute attribute = getAttribute(profileRequestContext);
        if (attribute == null) {
            return null;
        }

        final List<IdPAttributeValue> values = attribute.getValues();
        if (values.size() != 1) {
            log.warn("{}: Attribute '{}' has more than one value", getId(), getAttributeId());
            return null;
        }
        final IdPAttributeValue value = values.get(0);
        if (value instanceof final ScopedStringAttributeValue scopedStrAttributeValue) {
            logDebugFoundAttribute(attribute.getId(), scopedStrAttributeValue.getDisplayValue());
            return scopedStrAttributeValue.getDisplayValue();
        } else if (value instanceof final StringAttributeValue strValue) {
            logDebugFoundAttribute(attribute.getId(), strValue.getValue());
            return strValue.getValue();
        }

        log.warn("{}: Attribute '{}' could not be found", getId(), getAttributeId());
        return null;
    }

    private void logDebugFoundAttribute(String attributeId, String attributeValue) {
        if (log.isDebugEnabled()) {
            log.debug("{}: Found attribute '{}' with value '{}'", getId(), attributeId, attributeValue);
        }
    }

}
