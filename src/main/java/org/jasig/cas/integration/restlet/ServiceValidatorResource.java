package org.jasig.cas.integration.restlet;

import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.util.HttpClient;
import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
import org.jasig.cas.validation.Assertion;
import org.restlet.Context;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;
import org.restlet.resource.Representation;
import org.restlet.resource.Resource;
import org.restlet.resource.ResourceException;
import org.restlet.resource.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.Map;

import javax.validation.constraints.NotNull;

/**
 * Created with IntelliJ IDEA.
 * User: stevenc
 * Date: 9/3/12
 * Time: 4:10 PM
 * To change this template use File | Settings | File Templates.
 */
public class ServiceValidatorResource extends Resource {

    private final static Logger log = LoggerFactory.getLogger(ServiceValidatorResource.class);

    @Autowired
    private CentralAuthenticationService centralAuthenticationService;

    private String serviceTicketId;
    private String serviceTicketUrl;

    @Autowired
    @NotNull
    private HttpClient httpClient;

    public ServiceValidatorResource() {
    }

    public void init(final Context context, final Request request, final Response response) {
        super.init(context, request, response);
        this.serviceTicketId = (String) request.getAttributes().get("serviceTicketId");
        this.getVariants().add(new Variant(MediaType.APPLICATION_WWW_FORM));
    }

    public boolean allowDelete() {
        return false;
    }

    public boolean allowPost() {
        return true;
    }

    public void setHttpClient(final HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void removeRepresentations() throws ResourceException {
        getResponse().setStatus(Status.SUCCESS_OK);
    }

    public void acceptRepresentation(final Representation entity) throws ResourceException {
        final Form form = getRequest().getEntityAsForm();
        final String serviceUrl = form.getFirstValue("serviceTicketUrl");
        try {
            final Assertion authentication = this.centralAuthenticationService.validateServiceTicket(serviceTicketId, new SimpleWebApplicationServiceImpl(serviceUrl, this.httpClient));
            if (authentication.getChainedAuthentications().size() > 0) {
                // Iterate through each of the ChainedAuthentications and put them into the JSonArray
                JSONArray jsonResult = new JSONArray();
                for (Authentication auth : authentication.getChainedAuthentications()) {
                    // Create the principle
                    JSONObject principle = createJSONPrinciple(auth);
                    JSONObject jsonAuth = new JSONObject();
                    jsonAuth.put("authenticated_date", auth.getAuthenticatedDate());
                    jsonAuth.put("attributes", principle);
                    jsonResult.add(jsonAuth);
                }
                getResponse().setEntity(jsonResult.toJSONString(), MediaType.TEXT_PLAIN);
            } else {
                getResponse().setEntity(java.lang.String.format("\"{\"authenticated\":\"false\"}\""), MediaType.TEXT_PLAIN);
            }
        } catch (final TicketException e) {
            log.error(e.getMessage(), e);
            getResponse().setStatus(Status.CLIENT_ERROR_NOT_FOUND, "TicketGrantingTicket could not be found.");
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
            getResponse().setStatus(Status.CLIENT_ERROR_BAD_REQUEST, e.getMessage());
        }
    }

    private JSONObject createJSONPrinciple(Authentication auth) {
        Principal principal = auth.getPrincipal();
        JSONObject principle = new JSONObject();
        principle.put("id", principal.getId());
        JSONArray jsonResult = new JSONArray();
        for (Map.Entry<String, Object> entry : principal.getAttributes().entrySet()) {
            JSONObject attribute = new JSONObject();
            attribute.put(entry.getKey(), entry.getValue());
            jsonResult.add(attribute);
        }
        principle.put("attributes", jsonResult);
        return principle;
    }
}