package com.v2solve.app.security.utility.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class MultiJWTDecoder implements JwtDecoder 
{
	Map<String, JwtDecoder> decoderMap;
	
	@Override
	public Jwt decode(String token) throws JwtException 
	{
		HashMap<String, String> decoderErrorMessage = new HashMap<>();
		
		if (decoderMap == null)
			throw new JwtException("No Jwt Decoders registered to decode.");
		
		for (String decoderName: decoderMap.keySet())
		{
			JwtDecoder decoder = decoderMap.get(decoderName);
			
			try
			{
				Jwt decoded = decoder.decode(token);
				return decoded;
			}
			catch (Throwable e)
			{
				decoderErrorMessage.put(decoderName, e.getMessage());
			}
		}
		
		if (decoderErrorMessage.size() > 0)
		{
			String toString = decoderErrorMessage.toString();
			
			try
			{
				ObjectMapper om = new ObjectMapper ();
				toString = om.writeValueAsString(decoderErrorMessage);
			}
			catch (Throwable e)	{
				
			}
			
			throw new JwtException("None of the decoders could decode this token " + token + ", the messages are as follows:-" + toString);
		}

		throw new JwtException("None of the decoders could decode this token " + token);
	}

}
