package com.v2solve.app.security.utility.oauth2;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import reactor.core.publisher.Mono;



/**
 * The only reason this needs to be done is because JwtDecode does not have a custom validator that can be plugged.
 * @author Saurinya
 *
 */
public class CustomJwtDecoder implements JwtDecoder 
{
	String decoderName;
	NimbusReactiveJwtDecoder baseDecoder = null;

	public CustomJwtDecoder (String decoderName,String jwkSetUri)
	{
		this.decoderName = decoderName;
		this.baseDecoder = new NimbusReactiveJwtDecoder(jwkSetUri);
	}
	
	
	public void setValidator (OAuth2TokenValidator<Jwt> validator)
	{
		baseDecoder.setJwtValidator(validator);
	}
	
	
	@Override
	public Jwt decode(String token) throws JwtException 
	{
		Mono<Jwt> monoJwtM = baseDecoder.decode(token);
		return monoJwtM.block();
	}
	
}
