package com.devsuperior.bds04.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	private static final String[] PUBLIC = { "/oauth/token" };
	
	private static final String [] CLIENT_OR_ADMIN = { "/cities/**" , "/events/**" };
	
	private static final String[] ADMIN = { "/cities/**" };
	
	@Autowired
	private JwtTokenStore tokenStore;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
		.antMatchers(PUBLIC).permitAll()
		.antMatchers(HttpMethod.GET, CLIENT_OR_ADMIN).permitAll()
		.antMatchers(CLIENT_OR_ADMIN).hasAnyRole("CLIENT", "ADMIN")
		.antMatchers(ADMIN).hasAnyRole("ADMIN")
		.anyRequest().authenticated();
	}
	
}
