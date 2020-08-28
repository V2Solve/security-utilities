package com.v2solve.app.security.config;


import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Provider;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Registration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import com.v2solve.app.security.utility.oauth2.ClientCredentialManager;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties.CustomProvider;

import lombok.extern.slf4j.Slf4j;


/**
 * Use this class as configuration to enable oauth type web security. (meaning a logon page will be provided for logging on).
 * This is useful when the UI application is being served as a part of the spring boot application itself.
 * @author Saurin Magiawala
 *
 */
@Configuration
@Slf4j
public class ClientCredentialsSecurityConfig 
{
    
	@Bean
	ClientCredentialTokenServices clientCredentialTokenServices (@Autowired ClientCredentialSecurityProperties ccsp)
	{
		HashMap<String, ClientCredentialManager> mapOfClientCredentialManagers = new HashMap<>();
		ClientCredentialTokenServicesImpl cctsi = new ClientCredentialTokenServicesImpl();
		
		if (ccsp.isEnable() == false)
		{
			return cctsi;
		}
		
		 ExtendedOAuth2ClientProperties client = ccsp.getClient();
		 
		 if (client != null)
		 {
			 Map<String, Registration> regs = client.getRegistration();
			 Map<String, Provider> providers = client.getProvider();
			 Map<String, CustomProvider> customProviders = client.getProviderExtension();
			 
			 if (regs != null)
			 {
				 for (String regKey: regs.keySet())
				 {
					 Registration reg = regs.get(regKey);
					 Provider p = null;
					 CustomProvider cp = null;
					 if (providers != null) 
						 p = providers.get(regKey);
					 if (customProviders != null)
						 cp = customProviders.get(regKey);
					 ClientCredentialManager ccm = new ClientCredentialManager(regKey,reg,p,cp);
					 log.debug("Client Credential Manager for registration: " + regKey + " added to mapOfClientCredentialManagers");
					 mapOfClientCredentialManagers.put(regKey, ccm);
				 }
			 }
		 }
		 
		 cctsi.setMapOfClientCredentialManagers(mapOfClientCredentialManagers);
		 
		 log.info("ClientCredentialTokenServices bean initialized with " + mapOfClientCredentialManagers.size() + " providers.");
		 return cctsi;
	}
}