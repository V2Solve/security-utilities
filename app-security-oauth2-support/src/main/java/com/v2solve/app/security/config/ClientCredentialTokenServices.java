package com.v2solve.app.security.config;

import org.springframework.security.oauth2.core.OAuth2AccessToken;


public interface ClientCredentialTokenServices 
{
	/**
	 * The method looks into the map of configured token providers and if found one, will obtain a token
	 * using the configured credentials. If not found the provider name, then it will throw an exception.
	 * @param providerName
	 * @return
	 */
	public OAuth2AccessToken getTokenFor (String providerName);
	
	/**
	 * This method could be used when there is only provider configured.
	 * the method returns the token from the first provider available in the set.
	 * @return
	 */
	public OAuth2AccessToken getToken ();
}
