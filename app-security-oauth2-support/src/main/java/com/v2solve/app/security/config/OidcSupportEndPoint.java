package com.v2solve.app.security.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Provider;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Registration;
import org.springframework.http.MediaType;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties.CustomProvider;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * This class supports clients like angular to be able to read configuration and initiate login flows.
 * @author Saurinya
 *
 */
@RestController
@RequestMapping(path = "/oidc-support", produces = MediaType.APPLICATION_JSON_VALUE)
public class OidcSupportEndPoint 
{
	@Autowired
	WebSecurityProperties wsp;
	
	@RequestMapping(method = RequestMethod.GET,path="/client-registrations",produces = MediaType.APPLICATION_JSON_VALUE)
	public List<ClientConfiguration> getConfig ()
	{
		List<ClientConfiguration> listOfClientConfigurations = new ArrayList<>();
		
		ExtendedOAuth2ClientProperties client = wsp.getClient();
		
		Map<String, Registration> mapOfRegistrations = client.getRegistration();
		Map<String, Provider> mapOfProviders = client.getProvider();
		Map<String, CustomProvider> mapOfCustomProviders = client.getProviderExtension();
		
		if (mapOfRegistrations != null)
		{
			for (String regName: mapOfRegistrations.keySet())
			{
				Registration reg = mapOfRegistrations.get(regName);
				Provider p = null;
				CustomProvider cp = null;
				if (mapOfProviders != null)
					p = mapOfProviders.get(regName);
				
				if (mapOfCustomProviders != null)
					cp = mapOfCustomProviders.get(regName);
				
				if (reg != null)
				{
					Registration newR = new Registration(); 
					Provider newP = new Provider();
					CustomProvider newCp = new CustomProvider();
					
					ReflectionUtils.shallowCopyFieldState(reg, newR);
					if (p != null)
						ReflectionUtils.shallowCopyFieldState(p, newP);
					if (cp != null)
						ReflectionUtils.shallowCopyFieldState(cp, newCp);
					
					if (newR.getClientSecret() != null)
						newR.setClientSecret("--masked--");
					
					ClientConfiguration cc = new ClientConfiguration(newR,newP,newCp);
					listOfClientConfigurations.add(cc);
				}
			}
		}
		
		return listOfClientConfigurations;
	}
	
	
	@Data
	@AllArgsConstructor
	static class ClientConfiguration
	{
		Registration registration;
		Provider provider;
		CustomProvider custom;
	}
}
