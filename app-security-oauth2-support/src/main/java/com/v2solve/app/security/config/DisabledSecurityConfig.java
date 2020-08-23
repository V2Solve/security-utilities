package com.v2solve.app.security.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Conditional(ConfigConditions.DisableSecurity.class)
@Slf4j
public class DisabledSecurityConfig extends CommonConfigAdapter 
{
	
	@Autowired CommonSecurityProperties csp;
	

	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		log.warn("Security disabled!. Security is configured to allow all requests without Authentication.");
		
		setCommonConfiguration(http, csp);
    	
		http
	      .antMatcher("/**")
	      .authorizeRequests()
	      .anyRequest()
	      .permitAll();
	}	
}
