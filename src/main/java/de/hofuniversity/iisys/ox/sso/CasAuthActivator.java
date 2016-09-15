package de.hofuniversity.iisys.ox.sso;

import org.osgi.service.http.HttpService;

import com.openexchange.config.ConfigurationService;
import com.openexchange.osgi.HousekeepingActivator;


public class CasAuthActivator extends HousekeepingActivator
{
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CasAuthActivator.class);
    
    private static final String CALLBACK_PATH = "/ajax/cascallback";
    
    private static final String AUTH_PATH = "/ajax/casauth";

    @Override
    protected Class<?>[] getNeededServices()
    {
        return new Class<?>[] {ConfigurationService.class, HttpService.class};
    }

    @Override
    protected void handleAvailability(final Class<?> clazz)
    {
        LOG.warn("Absent service: {}", clazz.getName());
    }

    @Override
    protected void handleUnavailability(final Class<?> clazz)
    {
        LOG.info("Re-available service: {}", clazz.getName());
    }
    
    @Override
    protected void startBundle() throws Exception
    {
        LOG.info("activating CAS authentication");
        
        try
        {
            //register services
            Services.setServiceLookup(this);
            
            //register callback service for PGT reception
            HttpService httpService = getService(HttpService.class);
            httpService.registerServlet(CALLBACK_PATH, new CasCallbackServlet(), null, null);
            
            //register CAS authentication
            httpService.registerServlet(AUTH_PATH, new CasAuthServlet(), null, null);
            
            //TODO: logout servlet redirecting to CAS logout?
        }
        catch (final Throwable t)
        {
            LOG.error("failed to activate CAS authentication", t);
            throw t instanceof Exception ? (Exception) t : new Exception(t);
        }
    }

    @Override
    protected void stopBundle() throws Exception
    {
        try
        {
            HttpService service = getService(HttpService.class);
            if (service != null)
            {
                service.unregister(CALLBACK_PATH);
                service.unregister(AUTH_PATH);
            }
           
            cleanUp();
            Services.setServiceLookup(null);
        }
        catch (final Throwable t)
        {
            LOG.error("", t);
            throw t instanceof Exception ? (Exception) t : new Exception(t);
        }
    }
}
