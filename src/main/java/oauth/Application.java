package oauth;

import oauth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.*;

@ComponentScan
@EnableAutoConfiguration
@Configuration
//@EnableAuthorizationServer
public class Application {

    @Autowired
    UserDetailsService userDetailsService;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public InMemoryClientDetailsService inMemoryClientDetailsService(){
        InMemoryClientDetailsService inMemoryClientDetailsService = new InMemoryClientDetailsService();

        BaseClientDetails client = new BaseClientDetails("foo", null, "read", "password,refresh_token", "ROLE_USER");
        client.setAutoApproveScopes(new HashSet<String>(Arrays.asList("read")));
        client.setClientSecret("655f523128212d6e70634446224c2a48");
        client.setAccessTokenValiditySeconds(7200);
        client.setRefreshTokenValiditySeconds(30);
        inMemoryClientDetailsService.setClientDetailsStore(Collections.singletonMap("client", client));
        return inMemoryClientDetailsService;
    }

//    @Bean
//    public AuthorizationServerConfigurerAdapter AuthorizationServerConfigurerAdapter(){}

    @Autowired
    public void getAuthenticationManager(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService);
    }


    @Bean
    public ApplicationSecurity applicationSecurity() {

        return new ApplicationSecurity();
    }

    @Bean
    public AuthenticationSecurity authenticationSecurity() {

        return new AuthenticationSecurity();
    }

    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)

    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {


        @Override

        protected void configure(HttpSecurity http) throws Exception {

            http
                    .authorizeRequests()
                    .antMatchers("/**").hasRole("USER")
                    .and()

                    .formLogin();
        }

    }

    @Order(Ordered.HIGHEST_PRECEDENCE + 10)

    protected class AuthenticationSecurity extends GlobalAuthenticationConfigurerAdapter {


        @Override
        public void init(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService);

//            auth
//                    .inMemoryAuthentication()
//                    .withUser("user")
//                    .password("password")
//
//                    .roles("USER")
//                    .and()
//                    .withUser("adminr")
//                    .password("password")
//
//                    .roles("ADMIN", "USER");

        }
    }

//    @Configuration
//    @EnableAuthorizationServer
//    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
//
//        @Bean
//        public TokenStore tokenStore() {
//            return new InMemoryTokenStore();
//        }
//
//        @Autowired
//        AuthenticationManager authenticationManager;
//
//        @Override
//        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
//            endpoints
//                    .tokenStore(tokenStore())
//                    .authenticationManager(authenticationManager);
//
//        }
//
//        @Override
//        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//            clients
//                    .inMemory();
////                    .withClient('testApp')
////                    .scopes("read", "write")
////                    .authorities('ROLE_CLIENT')
////                    .authorizedGrantTypes("password","refresh_token")
////                    .secret('secret')
////                    .accessTokenValiditySeconds(7200)
//
//        }
//    }
}
