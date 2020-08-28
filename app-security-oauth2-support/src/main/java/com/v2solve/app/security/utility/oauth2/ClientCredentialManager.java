package com.v2solve.app.security.utility.oauth2;


import java.time.Instant;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Provider;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Registration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties.CustomProvider;


public class ClientCredentialManager 
{
	String regName;
	Registration registration;
	Provider provider;
	CustomProvider customProvider;
	
	ClientRegistration cr = null;
	
	public ClientCredentialManager (String regName,Registration registration,Provider provider,CustomProvider customProvider)
	{
		this.regName = regName;
		this.registration = registration;
		this.provider = provider;
		this.customProvider = customProvider;
		
		try 
		{
			cr = OAuth2Utils.buildClientRegistrationForClientCredentials(regName,registration,provider,customProvider);
		} 
		catch (RuntimeException re) 
		{
			throw re;
		} 
		catch (Throwable e) 
		{
			throw new RuntimeException(e);
		}
	}
	
	OAuth2AccessToken accessToken = null;
	
	public OAuth2AccessToken getAccessToken ()
	{
		Instant toCompare = Instant.now().minusSeconds(60);
		
		if (accessToken == null || accessToken.getExpiresAt().isAfter(toCompare))
		{
			synchronized (this) 
			{
				if (accessToken == null || accessToken.getExpiresAt().isAfter(toCompare))
				{
					accessToken = OAuth2Utils.getClientCredentialToken(cr);
				}
			}
		}
		
		return accessToken;
	}
}
