package com.v2solve.app.security.config;


import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;


import com.v2solve.app.security.utility.oauth2.MultiJWTDecoder;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;
import com.v2solve.app.security.utility.oauth2.OAuth2Utils;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Conditional(ConfigConditions.EnableJwtSecurity.class)
@Slf4j
public class JwtSecurityConfig extends CommonConfigAdapter {

    
    @Autowired
    CommonSecurityProperties commonSecurityProperties;
    
    @Autowired
    JwtSecurityProperties jwtSp;
    
	
	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		setCommonConfiguration(http, commonSecurityProperties);
		
		// Lets create the client repository..
		ExtendedOAuth2ClientProperties client = jwtSp.getClient();
		Map<String, JwtDecoder> mapOfDecoders = OAuth2Utils.getMapOfJwtDecoders(client);
		
		if (mapOfDecoders != null && !mapOfDecoders.isEmpty())
		{
			MultiJWTDecoder mjwtD = new MultiJWTDecoder(mapOfDecoders);
			http.oauth2ResourceServer().jwt().decoder(mjwtD);
		}
		else
		{
			log.error("No client registrations are available in the configuration, security may not behave as expected.");
			http.oauth2ResourceServer();
		}
		
		setCommonAuthPattern(http, commonSecurityProperties);
	}
}
