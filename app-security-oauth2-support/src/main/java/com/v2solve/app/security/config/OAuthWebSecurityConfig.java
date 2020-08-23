package com.v2solve.app.security.config;



import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;
import com.v2solve.app.security.utility.oauth2.OAuth2Utils;

import lombok.extern.slf4j.Slf4j;


/**
 * Use this class as configuration to enable oauth type web security. (meaning a logon page will be provided for logging on).
 * This is useful when the UI application is being served as a part of the spring boot application itself.
 * @author Saurin Magiawala
 *
 */
@Configuration
@Conditional(ConfigConditions.EnableOAuth2Security.class)
@Slf4j
public class OAuthWebSecurityConfig extends CommonConfigAdapter {

    @Autowired
    WebSecurityProperties wsp;
    
    @Autowired
    CommonSecurityProperties commonSecurityProperties;
    
    ClientRegistrationRepository configuredClientRegistrationRepository ()
    {
		try 
		{
			ExtendedOAuth2ClientProperties client = wsp.getClient();
			List<ClientRegistration> clientRegistrations = OAuth2Utils.getListOfClientRegistrations(client);
			if (clientRegistrations != null)
			{
				InMemoryClientRegistrationRepository imrC = new InMemoryClientRegistrationRepository(clientRegistrations);
				return imrC;
			}
		} 
		catch (RuntimeException e)
		{
			throw e;
		}
		catch (Throwable e)
		{
			throw new RuntimeException(e);
		}
		
		return null;
    }
    
	
	@Override
	protected void configure(HttpSecurity http) throws Exception 
	{
		setCommonConfiguration(http, commonSecurityProperties);
		
		ClientRegistrationRepository clientRepository = configuredClientRegistrationRepository();
		
		if (clientRepository == null)
		{
			log.error("No client registrations are available in the configuration, security may not behave as expected.");
			http.oauth2Login();
		}
		else
		{
			http.oauth2Login().clientRegistrationRepository(clientRepository);
		}
		
		setCommonAuthPattern(http, commonSecurityProperties);
	}
}