package fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.navigate;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.DataConnector;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl;
import net.shibboleth.idp.attribute.resolver.testing.MockAttributeDefinition;
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.testing.MockReloadableService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.annotation.Nullable;
import java.util.Collection;
import java.util.List;

public class AttributeContextStringLookupStrategyTest {

    private AttributeContextStringLookupStrategy strategy;

    protected ProfileRequestContext prc;

    protected RequestContext src;

    @BeforeMethod
    public void setup() throws Exception {
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
        strategy = new AttributeContextStringLookupStrategy();
        strategy.setId("Test AttributeContextStringLookupStrategy");
        strategy.setPrincipalNameLookupStrategy(new CanonicalUsernameLookupStrategy());

        final String idpAttrOne = "attributeOne";

        final IdPAttribute oneAttr = new IdPAttribute(idpAttrOne);
        oneAttr.setValues(CollectionSupport.singletonList(StringAttributeValue.valueOf("oneAttribute")));
        final AttributeDefinition oneAttrDef = new MockAttributeDefinition(idpAttrOne, oneAttr);
        oneAttrDef.initialize();

        final String idpAttrMultiple = "multiple";

        final IdPAttribute multiple = new IdPAttribute(idpAttrMultiple);
        multiple.setValues(List.of(StringAttributeValue.valueOf("oneAttribute"), StringAttributeValue.valueOf(null),
                StringAttributeValue.valueOf("twoAttribute")));
        final AttributeDefinition multipleAttrDef = new MockAttributeDefinition(idpAttrMultiple, multiple);
        multipleAttrDef.initialize();

        final String idpAttrScoped = "attributeScoped";

        final IdPAttribute scoped = new IdPAttribute(idpAttrScoped);
        scoped.setValues(List.of(ScopedStringAttributeValue.valueOf("scopeAttributeValue", "scope")));
        final AttributeDefinition scopedAttrDef = new MockAttributeDefinition(idpAttrScoped, scoped);
        scopedAttrDef.initialize();

        final String idpAttrMultipleScoped = "attributeMultipleScoped";

        final IdPAttribute multipleScoped = new IdPAttribute(idpAttrMultipleScoped);
        multipleScoped.setValues(List.of(ScopedStringAttributeValue.valueOf("oneValue", "scope"),
                ScopedStringAttributeValue.valueOf("twoValue", "scope")));
        final AttributeDefinition multipleScopedAttrDef = new MockAttributeDefinition(idpAttrMultipleScoped,
                multipleScoped);
        multipleScopedAttrDef.initialize();

        final AttributeResolverImpl resolver = newAttributeResolverImpl(
                List.of(oneAttrDef, multipleAttrDef, scopedAttrDef, multipleScopedAttrDef), null);
        strategy.setAttributeResolverService(new MockReloadableService<>(resolver));
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void invalid() throws ComponentInitializationException {
        // No attributeId
        strategy.initialize();
    }

    @Test
    public void testAttributeLookup() throws ComponentInitializationException {
        strategy.setAttributeId("attributeScoped");
        strategy.initialize();

        final SubjectCanonicalizationContext subjectCtx = prc.ensureSubcontext(SubjectCanonicalizationContext.class);
        subjectCtx.setPrincipalName("an-principal");

        final String scopedAttrValue = strategy.apply(prc);
        assertNotNull(scopedAttrValue);
        assertEquals(scopedAttrValue, "scopeAttributeValue@scope");
    }

    @Test
    public void testAttributeLookup_notFound() throws ComponentInitializationException {
        strategy.setAttributeId("anAttributeNotExisting");
        strategy.initialize();

        final SubjectCanonicalizationContext subjectCtx = prc.ensureSubcontext(SubjectCanonicalizationContext.class);
        subjectCtx.setPrincipalName("an-principal");

        final String attrValue = strategy.apply(prc);
        assertNull(attrValue);
    }

    @Test
    public void testAttributeLookup_manyValues() throws ComponentInitializationException {
        strategy.setAttributeId("attributeMultipleScoped");
        strategy.initialize();

        final SubjectCanonicalizationContext subjectCtx = prc.ensureSubcontext(SubjectCanonicalizationContext.class);
        subjectCtx.setPrincipalName("an-principal");

        final String attrValue = strategy.apply(prc);
        assertNull(attrValue);
    }

    @Test
    public void testAttributeLookup_NoSubjectContext() throws ComponentInitializationException {
        strategy.setAttributeId("multiple");
        strategy.initialize();

        final SubjectCanonicalizationContext subjectCtx = prc.ensureSubcontext(SubjectCanonicalizationContext.class);

        subjectCtx.removeFromParent();

        final String attrValue = strategy.apply(prc);
        assertNull(attrValue);
    }

    private static AttributeResolverImpl newAttributeResolverImpl(
            @Nullable final Collection<AttributeDefinition> definitions,
            @Nullable final Collection<DataConnector> connectors) throws ComponentInitializationException {
        final AttributeResolverImpl result = new AttributeResolverImpl();
        result.setId("test");

        result.setAttributeDefinitions(definitions == null ? CollectionSupport.emptyList() : definitions);
        result.setDataConnectors(connectors == null ? CollectionSupport.emptyList() : connectors);
        result.initialize();

        return result;
    }

}
