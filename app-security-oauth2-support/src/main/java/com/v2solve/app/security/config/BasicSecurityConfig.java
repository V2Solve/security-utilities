package com.v2solve.app.security.config;


import java.util.ArrayList;

import java.util.Base64;
import java.util.List;
import java.util.StringTokenizer;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;


import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@NoArgsConstructor
@Conditional(ConfigConditions.EnableBasicAuthSecurity.class)
public class BasicSecurityConfig extends CommonConfigAdapter 
{
    @Autowired 
    BasicSecurityProperties basicSecurityProperties;
    
    @Autowired
    CommonSecurityProperties commonSecurityProperties;
    
    @Bean
    public PasswordEncoder nativePasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    
	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		setCommonConfiguration(http, commonSecurityProperties);
		
		http.logout().logoutSuccessUrl("/index.html");
		
		http.httpBasic().authenticationEntryPoint(new BasicAuthenticationEntryPoint() {
			@Override
			public void afterPropertiesSet() {
				setRealmName(basicSecurityProperties.getRealm());
				super.afterPropertiesSet();
			}
		});
		
		
		setCommonAuthPattern(http, commonSecurityProperties);
	}
	
	
	/**
	 * Configures the global user list, by reading the users from the configuration properties.
	 * @param auth
	 * @param basicUserList
	 * @throws Exception
	 */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth,
    		@Autowired DataSource dataSource,
    		@Autowired Environment springEnv) 
    throws Exception 
    {
    	log.debug("configuring the jdbc authentication for basic auth.");
    	
    	auth.jdbcAuthentication()
    	    .dataSource(dataSource)
    	    .usersByUsernameQuery("select name as username,user_password as password,enabled from basic_auth_clients where name = ?")
    	    .authoritiesByUsernameQuery("select name as username,'ADMIN' as authority from basic_auth_clients where name = ?");
    	
    	List<BasicAuthUser> basicUserList = basicSecurityProperties.getUsers();
    		
    	if (basicUserList != null)
    	{
    		for (BasicAuthUser ui: basicUserList)
    		{
    			List<String> roles = new ArrayList<>();
    			
    			if (ui.getRoles() != null)
    			{
    				final StringTokenizer st = new StringTokenizer(ui.getRoles(),",; ");
    				while (st.hasMoreTokens())
    				{
    					roles.add(st.nextToken());
    				}
    			}
    			
    			log.debug("Adding user: " + ui.getUsername() + " with roles: " + roles);
    			log.debug("Authorization: " + "Basic " + Base64.getEncoder().encodeToString((ui.getUsername()+":"+ui.getPassword()).getBytes()));
    			
    			String rolesstr [] = roles.toArray(new String[0]);
    			
    	        auth.inMemoryAuthentication()
    	          .withUser(ui.getUsername()).password(nativePasswordEncoder().encode(ui.getPassword()))
    	          .authorities(rolesstr);
    		}
    	}
    	else
    	{
    		log.warn("No users have been configured for Basic Authentication, could not find configuration, v2solve.app.security.basic.users[0].username=..... and so forth");
    		log.warn("So at this point, only users present in the database may work for basic authentication");
    	}
    }    
}
