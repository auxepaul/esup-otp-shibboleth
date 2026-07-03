package fr.renater.shibboleth.idp.plugin.authn.esup.otp;

import java.io.IOException;

import net.shibboleth.idp.module.IdPModule;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;
import net.shibboleth.profile.module.ModuleException;
import net.shibboleth.profile.plugin.PluginException;
import net.shibboleth.shared.collection.CollectionSupport;

/**
 * Details about the Esup otp plugin.
 */
public class EsupOtpPlugin extends PropertyDrivenIdPPlugin {

    /**
     * Constructor.
     *
     * @throws IOException
     * @throws PluginException
     */
    public EsupOtpPlugin() throws IOException, PluginException {
        super(EsupOtpPlugin.class);
        try {
            final IdPModule module = new EsupOtpModule();
            setEnableOnInstall(CollectionSupport.singleton(module));
            setDisableOnRemoval(CollectionSupport.singleton(module));
        } catch (final IOException e) {
            throw e;
        } catch (final ModuleException e) {
            throw new PluginException(e);
        }
    }

}
