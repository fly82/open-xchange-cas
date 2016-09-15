package de.hofuniversity.iisys.ox.sso;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;

import com.openexchange.ajax.login.LoginConfiguration;
import com.openexchange.config.ConfigTools;
import com.openexchange.config.ConfigurationService;
import com.openexchange.configuration.ClientWhitelist;
import com.openexchange.configuration.CookieHashSource;
import com.openexchange.configuration.ServerConfig;
import com.openexchange.configuration.ServerConfig.Property;
import com.openexchange.java.Strings;
import com.openexchange.login.ConfigurationProperty;
import com.openexchange.sessiond.impl.IPRange;
import com.openexchange.tools.io.IOTools;

public class CasConfiguration
{
    public static final String CAS_URL_PROP = "autologin.cas.cas_url";
    public static final String CLEARPASS_URL_PROP = "autologin.cas.clearpass_url";
    public static final String OX_LOGIN_PROP = "autologin.cas.ox_login_url";
    public static final String PGT_CALLBACK_PROP = "autologin.cas.pgt_callback_url";

    public static final String STAY_SIGNED_IN_PROP = "autologin.stay_signed_in";
    
    public static final String DEBUG_LOG_PROP = "autologin.cas.debug_logging";
    
    public static final String CTX_NAME_PROP = "context_name";
    public static final String CLIENT_NAME_PROP = "client_name";
    public static final String UI_PATH_PROP = "ui_path";

    public static final String ERROR_PAGE_TEMPLATE = "<html>\n" + "<script type=\"text/javascript\">\n" + "// Display normal HTML for 5 seconds, then redirect via referrer.\n" + "setTimeout(redirect,5000);\n" + "function redirect(){\n" + " var referrer=document.referrer;\n" + " var redirect_url;\n" + " // If referrer already contains failed parameter, we don't add a 2nd one.\n" + " if(referrer.indexOf(\"login=failed\")>=0){\n" + "  redirect_url=referrer;\n" + " }else{\n" + "  // Check if referrer contains multiple parameter\n" + "  if(referrer.indexOf(\"?\")<0){\n" + "   redirect_url=referrer+\"?login=failed\";\n" + "  }else{\n" + "   redirect_url=referrer+\"&login=failed\";\n" + "  }\n" + " }\n" + " // Redirect to referrer\n" + " window.location.href=redirect_url;\n" + "}\n" + "</script>\n" + "<body>\n" + "<h1>ERROR_MESSAGE</h1>\n" + "</body>\n" + "</html>\n";
    
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CasConfiguration.class);
    
    //unique prefix for all configuration options
    private static final String
        PREFIX = "de.hofuniversity.iisys.ox.sso.";
    
    private static final String[] OPTIONS = {CAS_URL_PROP, CLEARPASS_URL_PROP,
        OX_LOGIN_PROP, PGT_CALLBACK_PROP, DEBUG_LOG_PROP, CTX_NAME_PROP, UI_PATH_PROP};
    
    /**
     * Reads the configuration, extracting property values into a key-value
     * map which is then returned.
     * 
     * @return map with configuration values, without the package prefix
     */
    public Map<String, String> getConfiguration()
    {
        Map<String, String> config = new HashMap<String, String>();
        
        ConfigurationService configService = Services.optService(
            ConfigurationService.class);
        
        String key = null;
        String value = null;
        for(String option : OPTIONS)
        {
            key = PREFIX + option;
            value = configService.getProperty(key);
            config.put(option, value);
        }
        
        return config;
    }
    
    public LoginConfiguration getLoginConfig(final ServletConfig config)
    {
        //from LoginServlet
        final String uiWebPath = config.getInitParameter(ServerConfig.Property.UI_WEB_PATH.getPropertyName());
        final boolean sessiondAutoLogin = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.SESSIOND_AUTOLOGIN.getPropertyName()));
        final CookieHashSource hashSource = CookieHashSource.parse(config.getInitParameter(Property.COOKIE_HASH.getPropertyName()));
        final String httpAuthAutoLogin = config.getInitParameter(ConfigurationProperty.HTTP_AUTH_AUTOLOGIN.getPropertyName());
        final String defaultClient = config.getInitParameter(ConfigurationProperty.HTTP_AUTH_CLIENT.getPropertyName());
        final String clientVersion = config.getInitParameter(ConfigurationProperty.HTTP_AUTH_VERSION.getPropertyName());
        final String templateFileLocation = config.getInitParameter(ConfigurationProperty.ERROR_PAGE_TEMPLATE.getPropertyName());
        String errorPageTemplate;
        if (null == templateFileLocation) {
            errorPageTemplate = ERROR_PAGE_TEMPLATE;
        } else {
            final File templateFile = new File(templateFileLocation);
            try {
                errorPageTemplate = IOTools.getFileContents(templateFile);
                LOG.info("Found an error page template at {}", templateFileLocation);
            } catch (final FileNotFoundException e) {
                LOG.error("Could not find an error page template at {}, using default.", templateFileLocation);
                errorPageTemplate = ERROR_PAGE_TEMPLATE;
            }
        }
        final int cookieExpiry = ConfigTools.parseTimespanSecs(config.getInitParameter(ServerConfig.Property.COOKIE_TTL.getPropertyName()));
        final boolean cookieForceHTTPS = Boolean.parseBoolean(config.getInitParameter(ServerConfig.Property.COOKIE_FORCE_HTTPS.getPropertyName())) || Boolean.parseBoolean(config.getInitParameter(ServerConfig.Property.FORCE_HTTPS.getPropertyName()));
        final boolean insecure = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.INSECURE.getPropertyName()));
        final boolean ipCheck = Boolean.parseBoolean(config.getInitParameter(ServerConfig.Property.IP_CHECK.getPropertyName()));
        final ClientWhitelist ipCheckWhitelist = new ClientWhitelist().add(config.getInitParameter(Property.IP_CHECK_WHITELIST.getPropertyName()));
        final boolean redirectIPChangeAllowed = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.REDIRECT_IP_CHANGE_ALLOWED.getPropertyName()));
        final List<IPRange> ranges = new LinkedList<IPRange>();
        final String tmp = config.getInitParameter(ConfigurationProperty.NO_IP_CHECK_RANGE.getPropertyName());
        if (tmp != null) {
            final String[] lines = Strings.splitByCRLF(tmp);
            for (String line : lines) {
                line = line.replaceAll("\\s", "");
                if (!line.equals("") && (line.length() == 0 || line.charAt(0) != '#')) {
                    ranges.add(IPRange.parseRange(line));
                }
            }
        }
        final boolean disableTrimLogin = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.DISABLE_TRIM_LOGIN.getPropertyName()));
        final boolean formLoginWithoutAuthId = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.FORM_LOGIN_WITHOUT_AUTHID.getPropertyName()));
        final boolean isRandomTokenEnabled = Boolean.parseBoolean(config.getInitParameter(ConfigurationProperty.RANDOM_TOKEN.getPropertyName()));
        
        LoginConfiguration conf = new LoginConfiguration(
            uiWebPath,
            sessiondAutoLogin,
            hashSource,
            httpAuthAutoLogin,
            defaultClient,
            clientVersion,
            errorPageTemplate,
            cookieExpiry,
            cookieForceHTTPS,
            insecure,
            ipCheck,
            ipCheckWhitelist,
            redirectIPChangeAllowed,
            ranges,
            disableTrimLogin,
            formLoginWithoutAuthId,
            isRandomTokenEnabled);
        
        return conf;
    }
}
