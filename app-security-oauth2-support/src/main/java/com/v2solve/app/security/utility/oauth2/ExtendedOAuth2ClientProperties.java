package com.v2solve.app.security.utility.oauth2;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
public class ExtendedOAuth2ClientProperties
		extends org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties {
	
	Map<String, CustomProvider> providerExtension = new HashMap<>();
		
	@Data
	public static class CustomProvider
	{
		Map<String,ClaimCheck> claimChecks = new HashMap<>();
	}
	
	@Data
	public static class ClaimCheck
	{
		List<String> allowedValues;
	}
}
