package oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.webserver.ClientAuthenticationCache;
import org.springframework.security.oauth2.provider.webserver.DefaultClientAuthenticationCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.TreeMap;

@Controller
public class AccessConfirmationController {

	private ClientAuthenticationCache authenticationCache = new DefaultClientAuthenticationCache();
	private ClientDetailsService clientDetailsService;

	public ClientAuthenticationCache getAuthenticationCache() {
		return authenticationCache;
	}

	@RequestMapping(value="/oauth/confirm_access")
	public ModelAndView accessConfirmation(HttpServletRequest request, HttpServletResponse response) {
		ClientAuthenticationToken clientAuth = getAuthenticationCache().getAuthentication(request, response);
	    if (clientAuth == null) {
	      throw new IllegalStateException("No client authentication request to authorize.");
	    }

	    ClientDetails client = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());
	    TreeMap<String, Object> model = new TreeMap<String, Object>();
	    model.put("auth_request", clientAuth);
	    model.put("client", client);
	    return new ModelAndView("access_confirmation", model);
	}
	

	public ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	@Autowired
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

}
