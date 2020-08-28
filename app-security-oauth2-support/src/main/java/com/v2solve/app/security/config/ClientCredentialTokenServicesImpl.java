package com.v2solve.app.security.config;

import java.util.HashMap;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.StringUtils;

import com.v2solve.app.security.utility.oauth2.ClientCredentialManager;

import lombok.Data;

@Data
public class ClientCredentialTokenServicesImpl implements ClientCredentialTokenServices 
{
	HashMap<String, ClientCredentialManager> mapOfClientCredentialManagers = new HashMap<>();

	@Override
	public OAuth2AccessToken getTokenFor(String providerName) 
	{
		if (StringUtils.isEmpty(providerName))
			throw new RuntimeException("providerName parameter must not be empty.");
		
		if (mapOfClientCredentialManagers != null)
		{
			ClientCredentialManager ccm = mapOfClientCredentialManagers.get(providerName);
			if (ccm == null)
				throw new RuntimeException("No Client Credential Manager configured for: " + providerName);
			return ccm.getAccessToken();
		}
		
		throw new RuntimeException("Nothing configured, no client credential manager available for " + providerName);
	}

	@Override
	public OAuth2AccessToken getToken() 
	{
		if (mapOfClientCredentialManagers != null && mapOfClientCredentialManagers.size() > 0)
		{
			for (String key: mapOfClientCredentialManagers.keySet())
			{
				return getTokenFor(key);
			}
		}
		
		throw new RuntimeException("Nothing configured, no client credential manager available");
	}
}
