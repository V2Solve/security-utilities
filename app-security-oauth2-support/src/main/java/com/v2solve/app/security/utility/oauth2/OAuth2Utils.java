package com.v2solve.app.security.utility.oauth2;


import java.net.MalformedURLException;
//import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Provider;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Registration;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties.ClaimCheck;
import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties.CustomProvider;

import reactor.core.publisher.Mono;

/**
 * Utility Functions for OAuth2
 * @author Saurinya
 *
 */
public class OAuth2Utils 
{
	static List<String> getScopesFromMetadata (OIDCProviderMetadata metadata)
	{
		Scope scope =  metadata.getScopes();
		if (scope == null)
			return Collections.singletonList(OidcScopes.OPENID);
		else
		{
			return scope.toStringList();
		}
	}
	
	static ClientAuthenticationMethod getPrioritizedAuthMethodFromMetadata (OIDCProviderMetadata metadata)
	{
		ClientAuthenticationMethod cAMethod = null;
		
		List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> clientAuthMethods = metadata.getTokenEndpointAuthMethods();
		
		// Lets check the client Authentication method.
		if (clientAuthMethods != null && clientAuthMethods.size()>0)
		{
			for (com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod ca: clientAuthMethods)
			{
				if (ca.getValue().toLowerCase().contains("post"))
				{
					cAMethod = ClientAuthenticationMethod.POST;
				}
			}
			
			if (cAMethod == null)
			{
				for (com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod ca: clientAuthMethods)
				{
					if (ca.getValue().toLowerCase().contains("basic"))
					{
						cAMethod = ClientAuthenticationMethod.BASIC;
					}
				}
			}
		}

		if (cAMethod == null)
			cAMethod = ClientAuthenticationMethod.POST;
		
		return cAMethod;
	}
	
	static ClientAuthenticationMethod getClientAuthMethodFromString (String clientAuthMethod)
	{
		if (StringUtils.isEmpty(clientAuthMethod))
			return null;
		else
			return new ClientAuthenticationMethod(clientAuthMethod);
	}
	
	static AuthenticationMethod getAuthenticationMethodFromString (String authMethod)
	{
		if (StringUtils.isEmpty(authMethod))
			return null;
		
		if (authMethod.equalsIgnoreCase(AuthenticationMethod.FORM.getValue()))
			return AuthenticationMethod.FORM;
		else if (authMethod.equalsIgnoreCase(AuthenticationMethod.HEADER.getValue()))
			return AuthenticationMethod.HEADER;
		else if (authMethod.equalsIgnoreCase(AuthenticationMethod.QUERY.getValue()))
			return AuthenticationMethod.QUERY;
		
		return null;
	}
	
	static AuthorizationGrantType getPrioritizedGrantTypeFromMetadata (OIDCProviderMetadata metadata)
	{
		AuthorizationGrantType grantType = AuthorizationGrantType.AUTHORIZATION_CODE;	// Default..
		
		List<GrantType> grantTypes = metadata.getGrantTypes();
		
		if (grantTypes != null)
		{
			if (grantTypes.contains(GrantType.AUTHORIZATION_CODE))
				grantType = AuthorizationGrantType.AUTHORIZATION_CODE;
			else if (grantTypes.contains(GrantType.IMPLICIT))
				grantType = AuthorizationGrantType.IMPLICIT;
			else if (grantTypes.contains(GrantType.CLIENT_CREDENTIALS))
				grantType = AuthorizationGrantType.CLIENT_CREDENTIALS;
			else if (grantTypes.contains(GrantType.PASSWORD))
				grantType = AuthorizationGrantType.PASSWORD;
			else if (grantTypes.contains(GrantType.REFRESH_TOKEN))
				grantType = AuthorizationGrantType.REFRESH_TOKEN;
		}
		
		return grantType;
	}
	
	static AuthorizationGrantType getAuthGrantTypeFromString (String authGrantType)
	{
		AuthorizationGrantType agt = null;
		
		if (StringUtils.isEmpty(authGrantType))
			agt = null;
		else
		{
			if (authGrantType.equalsIgnoreCase(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
				agt = AuthorizationGrantType.CLIENT_CREDENTIALS;
			else if (authGrantType.equalsIgnoreCase(AuthorizationGrantType.IMPLICIT.getValue()))
				agt = AuthorizationGrantType.IMPLICIT;
			else if (authGrantType.equalsIgnoreCase(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()))
				agt = AuthorizationGrantType.AUTHORIZATION_CODE;
			else if (authGrantType.equalsIgnoreCase(AuthorizationGrantType.PASSWORD.getValue()))
				agt = AuthorizationGrantType.PASSWORD;
			else if (authGrantType.equalsIgnoreCase(AuthorizationGrantType.REFRESH_TOKEN.getValue()))
				agt = AuthorizationGrantType.REFRESH_TOKEN;
		}
		
		return agt;
	}
	
	
	public static ClientRegistration buildFromProvider (String provider,String registrationId,String clientId) 
	throws MalformedURLException, ParseException
	{
		if (provider != null)
		{
			WebClient wc = WebClient.builder().baseUrl(provider).build();
			Mono<ClientResponse> crM = wc.get().uri(OIDCProviderConfigurationRequest.OPENID_PROVIDER_WELL_KNOWN_PATH, (Object)null).exchange();
			ClientResponse cr = crM.block();
			Mono<String> responseM = cr.bodyToMono(String.class);
			String response = responseM.block();
			OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(response);
			
			String issuerValue = metadata.getIssuer().getValue();
//			String issuerHost = null;
//			if (issuerValue != null)
//				issuerHost = URI.create(issuerValue).getHost();
			
			ClientAuthenticationMethod cAMethod = getPrioritizedAuthMethodFromMetadata(metadata);
			AuthorizationGrantType grantType = getPrioritizedGrantTypeFromMetadata(metadata);
			List<String> scopes = getScopesFromMetadata(metadata);
			Map<String,Object> providerConfigMetadata = new LinkedHashMap<>(metadata.toJSONObject());
			
			// Lets start building the Client Registration..
			Builder builder = ClientRegistration.withRegistrationId(registrationId);
			builder.clientName(issuerValue);
			builder.clientId(clientId);
			builder.clientSecret("Temporary");
			builder.userNameAttributeName(IdTokenClaimNames.SUB);
			builder.scope(scopes);
			builder.clientAuthenticationMethod(cAMethod);
			builder.authorizationGrantType(grantType);
			builder.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}");
			builder.authorizationUri(metadata.getAuthorizationEndpointURI().toASCIIString());
			builder.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
			builder.providerConfigurationMetadata(providerConfigMetadata);
			builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
			builder.tokenUri(metadata.getTokenEndpointURI().toASCIIString());
			return builder.build();
		}
		
		return null;
	}
	
	
	/**
	 * Builds the client registration taking defaults from the toCopyFrom if not available in reg, or provider..
	 * @param toCopyFrom
	 * @param regName
	 * @param reg
	 * @param provider
	 * @param copyScopes - if true will copy default scopes from the toCopyFrom (if scopes are null in reg). Otherwise will not.
	 * @return
	 */
	static ClientRegistration buildClientRegistrationFrom (ClientRegistration toCopyFrom,String regName,Registration reg,Provider provider,boolean copyScopes)
	{
		String registrationId = regName;
		String clientId = reg.getClientId();
		String clientSecret = reg.getClientSecret();
		String clientName  = reg.getClientName();
		
		if (StringUtils.isEmpty(clientName))
			clientName = regName;
		
		AuthorizationGrantType grantType = getAuthGrantTypeFromString(reg.getAuthorizationGrantType());
//		String providerUrl    = reg.getProvider();
		String redirectUri    = reg.getRedirectUri();
		ClientAuthenticationMethod clientAuthMethod = getClientAuthMethodFromString(reg.getClientAuthenticationMethod());
		Set<String> scopes = reg.getScope();
		
		String authorizationUri = null;
//		String issuerUri = null;
		String jwkSetUri = null;
		String tokenUri = null;
		AuthenticationMethod userInfoAuthMethod = null;
		String userInfoUri = null;
		String userNameAttribute = null;
		
		if (provider != null)
		{
			authorizationUri = provider.getAuthorizationUri();
//			issuerUri = provider.getIssuerUri();
			jwkSetUri = provider.getJwkSetUri();
			tokenUri  = provider.getTokenUri();
			userInfoAuthMethod = getAuthenticationMethodFromString(provider.getUserInfoAuthenticationMethod());
			userInfoUri = provider.getUserInfoUri();
			userNameAttribute = provider.getUserNameAttribute();
		}
		
		// Now that we have everything lets put defaults..
		if (toCopyFrom != null)
		{
			if (clientAuthMethod == null)
				clientAuthMethod = toCopyFrom.getClientAuthenticationMethod();
			
			if (grantType == null)
				grantType = toCopyFrom.getAuthorizationGrantType();
			
			if (StringUtils.isEmpty(redirectUri))
				redirectUri = toCopyFrom.getRedirectUriTemplate();
			
			if (scopes == null || scopes.isEmpty())
				if (copyScopes)
					scopes = toCopyFrom.getScopes();
			
			if (toCopyFrom.getProviderDetails() != null)
			{
				if (StringUtils.isEmpty(authorizationUri))
					authorizationUri = toCopyFrom.getProviderDetails().getAuthorizationUri();
				
				if (StringUtils.isEmpty(tokenUri))
					tokenUri = toCopyFrom.getProviderDetails().getTokenUri();
				
				if (StringUtils.isEmpty(jwkSetUri))
					jwkSetUri = toCopyFrom.getProviderDetails().getJwkSetUri();
				
				if (toCopyFrom.getProviderDetails().getUserInfoEndpoint() != null)
				{
					if (StringUtils.isEmpty(userNameAttribute))
						userNameAttribute = toCopyFrom.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
					
					if (userInfoAuthMethod == null)
						userInfoAuthMethod = toCopyFrom.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod();
				}
			}
			
		}
		
		// Now lets build the client registration..
		Builder builder =  ClientRegistration.withRegistrationId(registrationId);
		builder.clientId(clientId);
		builder.clientSecret(clientSecret);
		builder.clientName(clientName);
		builder.authorizationGrantType(grantType);
		builder.clientAuthenticationMethod(clientAuthMethod);
		builder.scope(scopes);
		builder.redirectUriTemplate(redirectUri);
		builder.authorizationUri(authorizationUri);
		builder.jwkSetUri(jwkSetUri);
		builder.tokenUri(tokenUri);
		builder.userInfoUri(userInfoUri);
		builder.userNameAttributeName(userNameAttribute);
		builder.userInfoAuthenticationMethod(userInfoAuthMethod);
		
		return builder.build();
	}
	
	
	public static List<ClientRegistration> getListOfClientRegistrations (ExtendedOAuth2ClientProperties client) 
	throws MalformedURLException, ParseException
	{
		
		List<ClientRegistration> listOfClientRegistrations = new ArrayList<>();
		
		if (client != null)
		{
			// Lets get the registrations one by one..
			Map<String, ExtendedOAuth2ClientProperties.Registration> regMap  = client.getRegistration();
			Map<String, ExtendedOAuth2ClientProperties.Provider> providerMap = client.getProvider();
			
			if (regMap != null)
			{
				for (String regName: regMap.keySet())
				{
					Registration reg = regMap.get(regName);
					Provider provider = providerMap.get(regName);
					
					if (reg != null)
					{
						String registrationId = regName;

						ClientRegistration toCopyFrom = null;
						
						if (reg.getProvider() != null)
						{
							toCopyFrom = buildFromProvider(reg.getProvider(),registrationId,"Temporary");
						}
						
						ClientRegistration cr = buildClientRegistrationFrom(toCopyFrom, regName, reg, provider, true);
						listOfClientRegistrations.add(cr);
					}
				}
			}
		}
		
		return listOfClientRegistrations;
	}
	

	/**
	 * 
	 * @param listOfRegistrations
	 * @return
	 * @throws ParseException 
	 * @throws MalformedURLException 
	 */
	public static Map<String,JwtDecoder> getMapOfJwtDecoders (ExtendedOAuth2ClientProperties client) 
	throws MalformedURLException, ParseException
	{
		Map<String, JwtDecoder> mapOfDecoders = new HashMap<>();
		
		if (client != null)
		{
			// Lets get the registrations one by one..
			Map<String, ExtendedOAuth2ClientProperties.Registration> regMap  = client.getRegistration();
			Map<String, ExtendedOAuth2ClientProperties.Provider> providerMap = client.getProvider();
			Map<String, ExtendedOAuth2ClientProperties.CustomProvider> providerExtension = client.getProviderExtension();

			if (regMap != null)
			{
				for (String regName: regMap.keySet())
				{
					Registration reg = regMap.get(regName);
					Provider p = providerMap.get(regName);
					CustomProvider cp = providerExtension.get(regName);
					
					CustomJwtDecoder cjd = null;
					
					if (p != null && p.getJwkSetUri() != null)
					{
						// Great, the JwkSetUri has been provided..
						cjd = new CustomJwtDecoder(regName, p.getJwkSetUri());
					}
					else
					{
						// Okay so provider p has not been given, lets try to get it from the provider url if any..
						String providerUrl = reg.getProvider();
						ClientRegistration cr = buildFromProvider(providerUrl,regName,"Temporary");
						if (cr != null && cr.getProviderDetails() != null)
						{
							String jwkSetUri = cr.getProviderDetails().getJwkSetUri();
							if (jwkSetUri != null)
							{
								cjd = new CustomJwtDecoder(regName, jwkSetUri);
								
							}
						}
					}
					
					// Let check to see any claim validators need to be added.
					if (cp != null && cp.getClaimChecks() != null)
					{
						Map<String,ClaimCheck> mapOfClaimChecks = cp.getClaimChecks();
						Map<String,List<String>> claimsToCheck = new HashMap<>();
						for (String claimName: mapOfClaimChecks.keySet())
						{
							ClaimCheck cc = mapOfClaimChecks.get(claimName);
							if (cc.getAllowedValues() != null && !cc.getAllowedValues().isEmpty())
							{
								claimsToCheck.put(claimName, cc.getAllowedValues());
							}
						}
						
						if (!claimsToCheck.isEmpty())
						{
							CustomTokenValidator ctv = new CustomTokenValidator(claimsToCheck);
							if (cjd != null)
								cjd.setValidator(ctv);
						}
					}
					
					if (cjd != null)
						mapOfDecoders.put(regName, cjd);
				}
			}
		}
		
		return mapOfDecoders;
	}
	

	/**
	 * Obtains a client token, by building a client registration object from the issuerDomain,
	 * 
	 * @param clientId
	 * @param clientSecret
	 * @param issuerDomain
	 * @return
	 */
	public static OAuth2AccessToken getClientCredentialToken (String clientId,String clientSecret,String issuerDomain)
	{
		return getClientCredentialToken(clientId, clientSecret, issuerDomain, null);
	}
	
	
	/**
	 * Builds a client registration for ClientCredentials Grant given a minimal data..
	 * @param clientId
	 * @param clientSecret
	 * @param issuerDomain
	 * @param scopes
	 * @return
	 */
	public static ClientRegistration buildClientRegistrationForClientCredentials (String clientId,String clientSecret,String issuerDomain,String [] scopes)
	{
		// Lets start from the issuerDomain..
		Builder builder = ClientRegistrations.fromIssuerLocation(issuerDomain);
		builder.clientId(clientId);
		
		ClientRegistration toCopyFrom = builder.build();
		
		Registration r = new Registration();
		r.setClientId(clientId);
		r.setClientName(clientId);
		r.setClientSecret(clientSecret);
		r.setAuthorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		if (scopes != null)
		{
			HashSet<String> scopeset = new HashSet<>();
			for (String str: scopes)
				scopeset.add(str);
			r.setScope(scopeset);
		}
		
		ClientRegistration cr = buildClientRegistrationFrom(toCopyFrom, clientId, r, null, false);
		return cr;
	}
	
	/**
	 * Obtains a client token, by building a client registration object from the issuerDomain,
	 * 
	 * @param clientId
	 * @param clientSecret
	 * @param issuerDomain
	 * @return
	 */
	public static OAuth2AccessToken getClientCredentialToken (String clientId,String clientSecret,String issuerDomain,String [] scopes)
	{
		ClientRegistration cr = buildClientRegistrationForClientCredentials(clientId, clientSecret, issuerDomain, scopes);
		return getClientCredentialToken(cr);
	}
	
	
	/**
	 * Given a client registration record, get an access token..
	 * @param cr
	 * @return
	 */
	public static OAuth2AccessToken getClientCredentialToken (ClientRegistration cr)
	{
		OAuth2ClientCredentialsGrantRequest o2cc = new OAuth2ClientCredentialsGrantRequest(cr);
		WebClientReactiveClientCredentialsTokenResponseClient wrcctr = new WebClientReactiveClientCredentialsTokenResponseClient();
		Mono<OAuth2AccessTokenResponse> responseM = wrcctr.getTokenResponse(o2cc);
		OAuth2AccessTokenResponse response = responseM.block();
		OAuth2AccessToken accessToken = response.getAccessToken();
		return accessToken;
	}

	
	public static ClientRegistration buildClientRegistrationForClientCredentials(String regName,
			Registration registration, Provider provider, CustomProvider customProvider) 
	throws MalformedURLException, ParseException 
	{
		String registrationId = regName;
		
		Registration rr = new Registration();
		ReflectionUtils.shallowCopyFieldState(registration, rr);
		rr.setAuthorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		
		ClientRegistration toCopyFrom = null;
		
		if (registration.getProvider() != null)
		{
			toCopyFrom = buildFromProvider(registration.getProvider(),registrationId,"Temporary");
		}
		
		ClientRegistration cr = buildClientRegistrationFrom(toCopyFrom, regName, rr, provider, false);
		
		return cr;
	}
}
