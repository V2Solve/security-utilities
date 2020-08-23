package com.v2solve.app.security.utility.oauth2;


import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class CustomTokenValidator implements OAuth2TokenValidator<Jwt> 
{
	Map<String, List<String>> valuesToCheckOnClaims;
	
	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) 
	{
		return validateClaims(token,valuesToCheckOnClaims);
	}
	
	
	OAuth2TokenValidatorResult validateClaims (Jwt token,Map<String, List<String>> claimValuesToCheck)
	{
		if (claimValuesToCheck == null || claimValuesToCheck.isEmpty())
			return OAuth2TokenValidatorResult.success();
		
		for (String claimToCheck: claimValuesToCheck.keySet())
		{
			boolean thisMatched = false;
			
			List<String> allowedValues = claimValuesToCheck.get(claimToCheck);
			if (allowedValues == null || allowedValues.isEmpty())
				continue;
			
			List<String> claimValues = token.getClaimAsStringList(claimToCheck);
			if (claimValues == null || claimValues.isEmpty())
				return OAuth2TokenValidatorResult.failure(new OAuth2Error("The claim " + claimToCheck + " was either absent on the token or does not contain valid values "));
		
			for (String claimValue: claimValues)
			{
				for (String checkValue: allowedValues)
				{
					if (checkValue.equals(claimValue))
					{
						thisMatched = true;	// Atlease one value matches..
						break;
					}
				}
			}
			
			if (!thisMatched)
			{
				return OAuth2TokenValidatorResult.failure(new OAuth2Error("The claim " + claimToCheck + " contains values " + claimValues + "  which does not contain valid values allowed:- " + allowedValues));
			}
		}

		return OAuth2TokenValidatorResult.success();
	}

}
