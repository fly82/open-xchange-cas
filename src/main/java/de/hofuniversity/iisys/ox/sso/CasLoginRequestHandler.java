package de.hofuniversity.iisys.ox.sso;

import static com.openexchange.login.Interface.HTTP_JSON;

import static com.openexchange.tools.servlet.http.Cookies.getDomainValue;
import static com.openexchange.tools.servlet.http.Tools.copyHeaders;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.openexchange.ajax.LoginServlet;
import com.openexchange.ajax.fields.LoginFields;
import com.openexchange.ajax.login.HashCalculator;
import com.openexchange.ajax.login.LoginConfiguration;
import com.openexchange.ajax.login.LoginRequestHandler;
import com.openexchange.ajax.login.LoginRequestImpl;
import com.openexchange.ajax.login.LoginTools;
import com.openexchange.authentication.LoginExceptionCodes;
import com.openexchange.authorization.Authorization;
import com.openexchange.authorization.AuthorizationService;
import com.openexchange.exception.OXException;
import com.openexchange.groupware.contexts.Context;
import com.openexchange.groupware.contexts.impl.ContextExceptionCodes;
import com.openexchange.groupware.contexts.impl.ContextStorage;
import com.openexchange.groupware.ldap.User;
import com.openexchange.groupware.ldap.UserStorage;
import com.openexchange.log.LogProperties;
import com.openexchange.login.internal.AddSessionParameterImpl;
import com.openexchange.mail.config.MailProperties;
import com.openexchange.session.Session;
import com.openexchange.sessiond.SessiondService;
import com.openexchange.tools.servlet.http.Cookies;
import com.openexchange.tools.servlet.http.Tools;

public class CasLoginRequestHandler implements LoginRequestHandler
{
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(CasLoginRequestHandler.class);
    
    private static final String CAS_USER_ATT = "CAS_USER";
    private static final String CAS_TICKET_ATT = "CAS_TICKET";
    private static final String CAS_OPTOUT_ATT = "CAS_OPTOUT";
    private static final String ORIGINAL_URL_ATT = "ORIGINAL_URL";
    
    private static final String TICKET_PARAM = "ticket";
    private static final String PGT_URL_PARAM = "pgtUrl";
    private static final String TARGET_PARAM = "targetService";
    
    private static final String OPT_OUT_PARAM = "casOptOut";
    private static final String CAS_LOGOUT_PARAM = "casLogout";
    
    private static final String SESSION_ID_COOKIE = "sessionid";
    
    private static final String TICKET_VAL_FRAG = "serviceValidate?service=";
    private static final String LOGIN_FRAG = "login?service=";
    private static final String LOGOUT_FRAG = "logout";
    private static final String PROXY_PGT_FRAG = "proxy?pgt=";
    
    private static final String CAS_USER_TAG = "<cas:user>";
    private static final String CAS_USER_END_TAG = "</cas:user>";
    private static final String CAS_PGT_TAG = "<cas:proxyGrantingTicket>";
    private static final String CAS_PGT_END_TAG = "</cas:proxyGrantingTicket>";
    private static final String CAS_PROXY_TICKET_TAG = "<cas:proxyTicket>";
    private static final String CAS_PROXY_TICKET_END_TAG = "</cas:proxyTicket>";
    private static final String CAS_CREDS_TAG = "<cas:credentials>";
    private static final String CAS_CREDS_END_TAG = "</cas:credentials>";
    
    private static final String REFERRER_HEADER = "referer";
    
    private final String fCasUrl;
    private final String fCasClearPassUrl;
    private final String fLoginUrl;
    private final String fPgtCallback;
    
    private final String fContextName;
    private final String fUiPath;
    
    private final LoginConfiguration fLoginConf;
    
    private final boolean fDebug;
    
    //services
    private final AuthorizationService fAuthService;
    private SessiondService fSessiondService;

    public CasLoginRequestHandler(LoginConfiguration lConf)
    {
        //read configuration from properties file
        CasConfiguration configUitl = new CasConfiguration();
        Map<String, String> conf = configUitl.getConfiguration();
        
        fCasUrl = conf.get(CasConfiguration.CAS_URL_PROP);
        fCasClearPassUrl = conf.get(CasConfiguration.CLEARPASS_URL_PROP);
        fLoginUrl = conf.get(CasConfiguration.OX_LOGIN_PROP);
        fPgtCallback = conf.get(CasConfiguration.PGT_CALLBACK_PROP);
        
        fContextName = conf.get(CasConfiguration.CTX_NAME_PROP);
        fUiPath = conf.get(CasConfiguration.UI_PATH_PROP);
        
        fLoginConf = lConf;
        
        //services, if available
        fAuthService = Authorization.getService();
        getSessiondService();
        
        fDebug = Boolean.parseBoolean(conf.get(CasConfiguration.DEBUG_LOG_PROP));
    }
    
    private SessiondService getSessiondService()
    {
        if(fSessiondService == null)
        {
            fSessiondService = SessiondService.SERVICE_REFERENCE.get();
        }
        
        return fSessiondService;
    }

    @Override
    public void handleRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        Tools.disableCaching(response);
        
        //TODO: this method should only be called for unauthenticated users
        //TODO: different request handler or servlet for logouts

        HttpSession session = request.getSession();
        
        // retrieve original URL before new session is created
        String origUrl = (String) session.getAttribute(ORIGINAL_URL_ATT);
        
        if(fDebug)
        {
            LOG.info("ClearPassAutoLogin executed");
        }
        
        String[] credentials = null;
        
        try
        {
            boolean handled = false;
            
            //check whether user wants to opt-out
            handled = handleOptOut(request, response, session);
            
            //check whether user wants to log out
            handled = (handled || handleLogout(request, response, session));
            
            //handle clearPass login process otherwise
            if(!handled)
            {
                credentials = retrieveCredentials(request, response, session);
            }
        }
        catch(Exception e)
        {
            LOG.warn("ClearPassHook Exception: ", e);
        }
        
        //actually log into open-xchange
        if(credentials != null)
        {
            try
            {
                final Context ctx = findContext(fContextName);
                final User user = findUser(ctx, credentials[0]);
                
                fAuthService.authorizeUser(ctx, user);
                
                // Create session
                final String authId = LoginTools.parseAuthId(request, false);
//                final String client = LoginTools.parseClient(request, false, fLoginConf.getDefaultClient());
                // TODO: make configurable
                final String client = "open-xchange-appsuite";
                final String clientIP = LoginTools.parseClientIP(request);
                final String userAgent = LoginTools.parseUserAgent(request);
                final Map<String, List<String>> headers = copyHeaders(request);
                final com.openexchange.authentication.Cookie[] cookies = Tools.getCookieFromHeader(request);
                final String httpSessionId = request.getSession(true).getId();
                String hash = HashCalculator.getInstance().getHash(request, client);
                LoginRequestImpl logReq = new LoginRequestImpl(
                    credentials[0],
                    credentials[1],
                    clientIP,
                    userAgent,
                    authId,
                    client,
                    null,
                    hash,
                    HTTP_JSON,
                    headers,
                    cookies,
                    Tools.considerSecure(request, fLoginConf.isCookieForceHTTPS()),
                    request.getServerName(),
                    request.getServerPort(),
                    httpSessionId);

                AddSessionParameterImpl sessParam = new AddSessionParameterImpl(
                    credentials[0], logReq, user, ctx);
                final Session sess = getSessiondService().addSession(sessParam);
                
                if (null == sess)
                {
                    throw LoginExceptionCodes.UNKNOWN.create(
                        "Session could not be created.");
                }
                response.addCookie(new Cookie(SESSION_ID_COOKIE, sess.getSessionID()));
                
                //send response
                Tools.disableCaching(response);
                
                // write secret session cookie (needs to be secure)
                writeSecretCookie(request, response, sess, hash,
                    true, request.getServerName());
                
                // send redirect to UI
                if(origUrl == null)
                {
                    origUrl = LoginTools.generateRedirectURL(
                        request.getParameter(LoginFields.UI_WEB_PATH_PARAM),
                        // store session
                        "true",
                        sess.getSessionID(),
                        // does not work with configured path
//                        fLoginConf.getUiWebPath()));
                        fUiPath);
                    
                    Logger.getLogger("SSO").log(Level.INFO,
                        "### redirecting to generated url: " + origUrl);
                    response.sendRedirect(origUrl);
                }
                else
                {
                    //TODO: send stored original request url instead
                    
                    origUrl += "#session=" + sess.getSessionID();
                    origUrl += "&store=true";

                    Logger.getLogger("SSO").log(Level.INFO,
                        "### redirecting to stored url: " + origUrl);
                    response.sendRedirect(origUrl);
                    
                    //TODO: could the UI WEB path do that?
                }
            }
            catch(Exception e)
            {
                LOG.error("Failed to log in user: ", e);
            }
        }
    }
    
    private String[] retrieveCredentials(HttpServletRequest request,
        HttpServletResponse response, HttpSession session) throws Exception
    {
        String remoteUserId = null;
        String ticket = null;
        String tgt = null;
        String password = null;
    
        //user already logged in with CAS?
        remoteUserId = (String) session.getAttribute(CAS_USER_ATT);
    
        if(fDebug)
        {
            LOG.info("\tremoteUserId: " + remoteUserId);
        }
        
        //if no user is logged in, determine which step of the authentication
        //we are at
        String[] replyData = null;
        if(remoteUserId == null)
        {
            //replyData will contain a userId and a ticket granting ticket IOU
            
            //get ticket from request for clearpass-request
            String[] tickets = request.getParameterValues(TICKET_PARAM);
            if(tickets != null && tickets.length > 0)
            {
                ticket = tickets[0];
                session.setAttribute(CAS_TICKET_ATT, ticket);
    
                if(fDebug)
                {
                    LOG.info("\tgot ticket: " + ticket);
                }
                
                //try verifying received ticket
                replyData = handleLogin(ticket);
            }
            else if(session.getAttribute(CAS_TICKET_ATT) != null)
            {
                //extra ticket-fallback if OX stacks redirects that would cause an infinite loop
                //TODO: taken from Liferay - still needed?
                ticket = (String) session.getAttribute(CAS_TICKET_ATT);
    
                if(fDebug)
                {
                    LOG.info("\tsession ticket: " + ticket);
                }
                
                //try verifying stored ticket
                replyData = handleLogin(ticket);
            }
            
            //response from ticket verification
            if(replyData != null)
            {
                if(replyData[0] != null)
                {
                    remoteUserId = replyData[0];
                }
                
                //user IOU to get ticket
                if(fDebug)
                {
                    LOG.info("\tusing tgt iou: " + replyData[1]);
                }
                tgt = CasCallbackServlet.getTicket(replyData[1]);
                if(fDebug)
                {
                    LOG.info("\textracted tgt: " + tgt);
                }
            }
    
            //if no ticket has been received yet, trigger the CAS login sequence
            if(ticket == null)
            {
                if(fDebug)
                {
                    LOG.info("\tno ticket");
                }
                
                //store current URL
//                session.setAttribute(ORIGINAL_URL_ATT, getRequestUrl(request));
                
                // not a filter anymore, retrieve from referer
                String origUrl = request.getHeader(REFERRER_HEADER);
                
                Logger.getLogger("SSO").log(Level.INFO,
                    "### storing original url: " + origUrl);
                session.setAttribute(ORIGINAL_URL_ATT, origUrl);
                
                //send redirect to CAS login
                String url = fCasUrl + LOGIN_FRAG + fLoginUrl;
                
                response.sendRedirect(url);
            }
    
            //user clearpass using the ticket granting ticket
            if(tgt != null)
            {
                 password = retrievePassword(tgt);
            }
            
            //collect credentials
            if(remoteUserId != null)
            {
                //construct credentials array
                replyData = getCredentials(remoteUserId, password);
                
                //redirect back to original request url
                //TODO: disabled in favor of OX redirect - would only work for filters
//                String origUrl = (String) session.getAttribute(ORIGINAL_URL_ATT);
//                if(origUrl != null)
//                {
//                    if(fDebug)
//                    {
//                        LOG.info("redirecting back to: " + origUrl);
//                    }
//                    session.removeAttribute(ORIGINAL_URL_ATT);
//                    
//                    response.sendRedirect(origUrl);
//                    request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT_AND_CONTINUE, origUrl);
//                }
                
                //clear temporary variables
                session.removeAttribute(CAS_USER_ATT);
                session.removeAttribute(CAS_TICKET_ATT);
                session.removeAttribute(ORIGINAL_URL_ATT);
                
                return replyData;
            }
        }
        
        return null;
    }
    
    private String getRequestUrl(HttpServletRequest request)
    {
        //construct full request URL
        return request.getScheme() + "://" +
          request.getServerName() + 
            ("http".equals(request.getScheme()) && request.getServerPort() == 80
            || "https".equals(request.getScheme()) && request.getServerPort() == 443
            ? "" : ":" + request.getServerPort() ) +
          request.getRequestURI() +
            (request.getQueryString() != null
            ? "?" + request.getQueryString() : "");
    }
    
    private String[] handleLogin(String ticket) throws Exception
    {
        String userName = null;
        String pgtIou = null;
        
        //verify the given ticket, retrieve user name and PGT IOU
        String casUrl = fCasUrl + TICKET_VAL_FRAG
                + fLoginUrl + "&" + TICKET_PARAM + "=" + ticket;
        
        //also get proxy ticket through callback
        casUrl += "&" + PGT_URL_PARAM + "=" + fPgtCallback;
        
        String reply = sendRequest(casUrl);
        
        if(fDebug)
        {
            LOG.info("\tgot validation: " + reply);
        }
        
        boolean error = false;
        if(reply.indexOf(CAS_USER_TAG) > 0)
        {
            userName = reply.substring(reply.indexOf(CAS_USER_TAG) + CAS_USER_TAG.length(),
                    reply.indexOf(CAS_USER_END_TAG));
        }
        else
        {
            LOG.error("failed to extract user name from CAS validation response");
            error = true;
        }
        
        if(reply.indexOf(CAS_PGT_TAG) > 0)
        {
            pgtIou = reply.substring(reply.indexOf(CAS_PGT_TAG) + CAS_PGT_TAG.length(),
                    reply.indexOf(CAS_PGT_END_TAG));
        }
        else
        {
            LOG.error("failed to extract PGT IOU from CAS validation response");
            error = true;
        }
        
        if(error)
        {
            throw new Exception("failed to process CAS validation response:\n" + reply);
        }
        else
        {
            return new String[] {userName, pgtIou};
        }
    }
    
    private String[] getCredentials(String userName, String password)
    {
        //TODO: imported from liferay, array not needed anymore - method only for debugging
        if(fDebug)
        {
            LOG.info("\tuser: " + userName);
        }
        
        String[] credentials = new String[2];

        credentials[0] = userName;
        credentials[1] = password;

        if(fDebug)
        {
            LOG.info("\treturning: " + credentials[0]
                    + " - " + credentials[1]);
        }
        
        return credentials;
    }
    
    private String retrievePassword(String tgt) throws Exception
    {
        String password = null;
        String proxyTicket = null;
        
        //retrieve proxy ticket for CAS' clearpass service
        //(proxied authentication in the name of the user)
        String casUrl = fCasUrl + PROXY_PGT_FRAG + tgt
                + "&" + TARGET_PARAM + "=" + fCasClearPassUrl;
        
        String response = sendRequest(casUrl);
        
        if(fDebug)
        {
            LOG.info("\tproxy ticket response: " + response);
        }
        
        if(response.indexOf(CAS_PROXY_TICKET_TAG) > 0)
        {
            proxyTicket = response.substring(response.indexOf(CAS_PROXY_TICKET_TAG)
                    + CAS_PROXY_TICKET_TAG.length(), response.indexOf(CAS_PROXY_TICKET_END_TAG));
        }
        else
        {
            LOG.error("failed to retrieve proxy ticket from CAS response: " + response);
        }
        
        if(proxyTicket != null)
        {
            //retrieve clearpass credentials using proxy ticket
            casUrl = fCasClearPassUrl + "?" + TICKET_PARAM + "=" + proxyTicket;
            
            try
            {
                response = sendRequest(casUrl);
                
                if(fDebug)
                {
                    LOG.info("\tclearpass response: " + response);
                }
                
                if(response.indexOf(CAS_CREDS_TAG) > 0)
                {
                    password = response.substring(response.indexOf(CAS_CREDS_TAG)
                        + CAS_CREDS_TAG.length(), response.indexOf(CAS_CREDS_END_TAG));
                }
                else
                {
                    LOG.error("failed to retrieve password from CAS response: " + response);
                }
            }
            catch(Exception e)
            {
                LOG.error("failed to retrieve clearpass credentials", e);
            }
        }
        
        if(password == null)
        {
            LOG.error("failed to retrieve password, continuing without it");
        }
        
        return password;
    }
    
    private boolean handleOptOut(HttpServletRequest request,
            HttpServletResponse response, HttpSession session) throws Exception
    {
        boolean optOut = false;
        
        //get existing opt-out flag from session
        Boolean optOutAtt = (Boolean) session.getAttribute(CAS_OPTOUT_ATT);
        if(optOutAtt != null)
        {
            optOut = optOutAtt;
        }
        
        //get flag override from parameters
        String[] optOutVals = request.getParameterValues(OPT_OUT_PARAM);
        if(optOutVals != null && optOutVals.length > 0)
        {
            optOut = Boolean.parseBoolean(optOutVals[0]);
        }
        
        //set or clear flag
        if(optOut)
        {
            if(fDebug)
            {
                LOG.info("setting autologin opt-out flag");
            }
            
            session.setAttribute(CAS_OPTOUT_ATT, optOut);
        }
        else
        {
            session.removeAttribute(CAS_OPTOUT_ATT);
        }
        
        return optOut;
    }
    
    private boolean handleLogout(HttpServletRequest request,
            HttpServletResponse response, HttpSession session) throws Exception
    {
        boolean logout = false;
        
        String[] logoutVals = request.getParameterValues(CAS_LOGOUT_PARAM);
        if(logoutVals != null && logoutVals.length > 0)
        {
            logout = Boolean.parseBoolean(logoutVals[0]);
        }
        
        if(logout)
        {
            if(fDebug)
            {
                LOG.info("logout: clearing autologin session attributes");
            }
            
            //TODO: actually log out of open-xchange?
            //TODO: probably not the right ID
//            String sessId = request.getSession().getId();
//            fSessiondService.removeSession(sessId);
            
            //clear own variables
            session.removeAttribute(CAS_USER_ATT);
            session.removeAttribute(CAS_TICKET_ATT);
            
            //TODO: also clear opt-out flag?
            
            //redirect to CAS logout
            String url = fCasUrl + LOGOUT_FRAG;
            
            response.sendRedirect(url);
        }
        
        return logout;
    }
    
    private String sendRequest(String url) throws Exception
    {
        String reply = null;
        
        URL reqUrl = new URL(url);

        final HttpURLConnection connection =
            (HttpURLConnection) reqUrl.openConnection();

        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(
            connection.getInputStream()));
        final StringBuffer resBuff = new StringBuffer();
        String line = reader.readLine();
        while(line != null)
        {
            resBuff.append(line);
            resBuff.append("\r\n");
            line = reader.readLine();
        }
        reply = resBuff.toString();
        reader.close();
        
        return reply;
    }
    
    private Context findContext(final String contextInfo) throws OXException
    {
        final ContextStorage contextStor = ContextStorage.getInstance();
        final int contextId = contextStor.getContextId(contextInfo);
        if (ContextStorage.NOT_FOUND == contextId)
        {
            throw ContextExceptionCodes.NO_MAPPING.create(contextInfo);
        }
        final Context context = contextStor.getContext(contextId);
        if (null == context)
        {
            throw ContextExceptionCodes.NOT_FOUND.create((contextId));
        }
        return context;
    }
    
    private User findUser(final Context ctx, final String userInfo)
        throws OXException
    {
        final String proxyDelimiter =
            MailProperties.getInstance().getAuthProxyDelimiter();
        final UserStorage us = UserStorage.getInstance();
        int userId = 0;
        if (null != proxyDelimiter && userInfo.contains(proxyDelimiter))
        {
            userId = us.getUserId(userInfo.substring(userInfo.indexOf(
                proxyDelimiter) + proxyDelimiter.length(), userInfo.length()),
                ctx);
        }
        else
        {
            userId = us.getUserId(userInfo, ctx);
        }
        return us.getUser(userId, ctx);
    }
    
    //from loginservlet
    public void writeSecretCookie(HttpServletRequest req, HttpServletResponse resp, Session session, String hash, boolean secure, String serverName) {
        Cookie cookie = new Cookie(LoginServlet.SECRET_PREFIX + hash, session.getSecret());
        configureCookie(cookie, secure, serverName);
        resp.addCookie(cookie);

        writePublicSessionCookie(req, resp, session, secure, serverName);
    }
    
    public boolean writePublicSessionCookie(final HttpServletRequest req, final HttpServletResponse resp, final Session session, final boolean secure, final String serverName) {
        final String altId = (String) session.getParameter(Session.PARAM_ALTERNATIVE_ID);
        if (null != altId) {
            final Cookie cookie = new Cookie(getPublicSessionCookieName(req), altId);
            configureCookie(cookie, secure, serverName);
            resp.addCookie(cookie);
            return true;
        }
        return false;
    }

    public void configureCookie(final Cookie cookie, final boolean secure, final String serverName) {
        cookie.setPath("/");
        if (secure || (fLoginConf.isCookieForceHTTPS() && !Cookies.isLocalLan(serverName))) {
            cookie.setSecure(true);
        }
        if (fLoginConf.isSessiondAutoLogin() || fLoginConf.getCookieExpiry() < 0) {
            /*
             * A negative value means that the cookie is not stored persistently and will be deleted when the Web browser exits. A zero
             * value causes the cookie to be deleted.
             */
            cookie.setMaxAge(fLoginConf.getCookieExpiry());
        }
        final String domain = getDomainValue(null == serverName ? determineServerNameByLogProperty() : serverName);
        if (null != domain) {
            cookie.setDomain(domain);
        }
    }
    
    public String getPublicSessionCookieName(final HttpServletRequest req) {
        return new StringBuilder("open-xchange-public-session-".intern())
            .append(HashCalculator.getInstance().getUserAgentHash(req)).toString();
    }
    
    private String determineServerNameByLogProperty() {
        final String serverName = LogProperties.getLogProperty(LogProperties.Name.GRIZZLY_SERVER_NAME);
        return serverName;
    }
}
