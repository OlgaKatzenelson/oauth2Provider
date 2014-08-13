package oauth;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Handles requests for the application home page.
 */
@Controller
public class HomeController {


	/**
	 * Simply selects the home view to render by returning its name.
	 */
	@RequestMapping(value="/cvs", method=RequestMethod.GET)
	@ResponseBody
	public String loadCV() {
		StringBuilder cv = new StringBuilder();
		cv.append("Curriculum Vitae -- Name: ").append(getUserName()).append(" Experience: Java, Spring Security, ...");
		return cv.toString();
	}
	
	private String getUserName() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		if (principal instanceof UserDetails) {
		  username = ((UserDetails)principal).getUsername();
		} else {
		  username = principal.toString();
		}
		return username;
	}
	
}

