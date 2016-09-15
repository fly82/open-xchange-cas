package de.hofuniversity.iisys.ox.sso;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CasCallbackServlet extends HttpServlet
{
    static final long serialVersionUID = 7619729101856562529L;
    
    private static final String PGT_PARAM = "pgtId";
    private static final String PGT_IOU_PARAM = "pgtIou";
    
    //TODO: use callback?
    private static final Map<String, String> fTickets =
            new HashMap<String, String>();


    /**
     * @param iou proxy granting ticket IOU to get a ticket for
     * @return received proxy granting ticket or null
     */
    public static final String getTicket(String iou)
    {
        return fTickets.remove(iou);
    }
    
    @Override
    protected void doGet(final HttpServletRequest request,
        final HttpServletResponse response) throws ServletException, IOException
    {
        String pgtId = request.getParameter(PGT_PARAM);
        String pgtIou = request.getParameter(PGT_IOU_PARAM);
        
        if(pgtId != null || pgtIou != null)
        {
            fTickets.put(pgtIou, pgtId);
        }
        
        response.setStatus(200);
    }


    @Override
    protected void service(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        // create a new HttpSession if it's missing
        req.getSession(true);
        super.service(req, resp);
    }
}
