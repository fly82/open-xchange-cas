package de.hofuniversity.iisys.ox.sso;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.openexchange.ajax.login.LoginConfiguration;

public class CasAuthServlet extends HttpServlet
{
    private static final long serialVersionUID = 120693050315506816L;

    private CasLoginRequestHandler fReqHandler;
    
    @Override
    public void init(final ServletConfig config) throws ServletException
    {
        super.init(config);

        LoginConfiguration lConf = new CasConfiguration().getLoginConfig(config);
        fReqHandler = new CasLoginRequestHandler(lConf);
    }

    @Override
    protected void doGet(final HttpServletRequest request,
        final HttpServletResponse response) throws ServletException, IOException
    {
        fReqHandler.handleRequest(request, response);
    }

    //TODO: cover other methods?
    
    @Override
    protected void service(final HttpServletRequest req, final HttpServletResponse resp)
        throws ServletException, IOException
    {
        // create a new HttpSession if it's missing
        req.getSession(true);
        super.service(req, resp);
    }
}
