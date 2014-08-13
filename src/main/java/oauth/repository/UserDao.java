package oauth.repository;

import oauth.model.Role;
import oauth.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserDao {
 
    public User loadUserByUsername(final String username) {
        User user = new User();
        user.setFirstName("firstName");
        user.setLastName("lastName");
        user.setUsername("user");
        user.setPassword("1111");
        Role r = new Role();
        r.setName("ROLE_USER");
        List<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
        roles.add(r);
        user.setAuthorities(roles);
        return user;
    }
}