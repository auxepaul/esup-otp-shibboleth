package fr.renater.shibboleth.idp.plugin.authn.esup.otp.impl;

import fr.renater.shibboleth.idp.plugin.authn.esup.otp.context.EsupOtpContext;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.FunctionSupport;
import org.opensaml.core.testing.OpenSAMLInitBaseTestCase;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import java.util.List;

/** Base class for further action tests. */
public class BaseAuthenticationContextTest extends OpenSAMLInitBaseTestCase {

    protected RequestContext src;
    protected ProfileRequestContext prc;
    protected AuthenticationContext ac;
    protected EsupOtpContext eoc;
    protected List<AuthenticationFlowDescriptor> authenticationFlows;

    protected void initializeMembers() throws ComponentInitializationException {
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
        ac = new AuthenticationContext();
        prc.addSubcontext(ac, true);

        authenticationFlows = List.of(new AuthenticationFlowDescriptor(), new AuthenticationFlowDescriptor(),
                new AuthenticationFlowDescriptor());
        authenticationFlows.get(0).setId("test1");
        authenticationFlows.get(1).setId("test2");
        authenticationFlows.get(1).setPassiveAuthenticationSupported(true);
        authenticationFlows.get(2).setId("test3");
    }

    protected void setUp() throws ComponentInitializationException {
        initializeMembers();

        final PopulateAuthenticationContext action = new PopulateAuthenticationContext();
        assert authenticationFlows != null;
        action.setAvailableFlows(authenticationFlows);
        action.setPotentialFlowsLookupStrategy(FunctionSupport.constant(authenticationFlows));
        action.initialize();

        action.execute(src);
    }

    @Nonnull
    protected final MockHttpServletRequest getMockHttpServletRequest(final AbstractAuthenticationAction action) {
        assert action != null;
        final HttpServletRequest req = action.getHttpServletRequest();
        assert req != null;
        return (MockHttpServletRequest) req;
    }

    protected void addEsupOtpContext() {
        eoc = new EsupOtpContext();
        eoc.setUsername("jdoe");
        ac.addSubcontext(eoc, true);
    }

}
