package com.v2solve.app.security.config;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * This class contains all the other configuration conditions for this project.
 * @author Saurinya
 *
 */

public class ConfigConditions 
{
	
	public static class DisableSecurity implements Condition
	{
		@Override
		public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) 
		{
			Boolean b = Boolean.parseBoolean(context.getEnvironment().getProperty("v2solve.app.security.disable","false"));
			return b;
		}
	}

	public static class EnableBasicAuthSecurity implements Condition
	{
		@Override
		public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) 
		{
			Boolean b = Boolean.parseBoolean(context.getEnvironment().getProperty("v2solve.app.security.basic.enable","false"));
			return b;
		}
	}
	
	
	public static class EnableOAuth2Security implements Condition
	{
		@Override
		public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) 
		{
			Boolean b = Boolean.parseBoolean(context.getEnvironment().getProperty("v2solve.app.security.oauth2.enable","false"));
			return b;
		}
	}	
	
	public static class EnableJwtSecurity implements Condition
	{
		@Override
		public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) 
		{
			Boolean b = Boolean.parseBoolean(context.getEnvironment().getProperty("v2solve.app.security.jwt.enable","false"));
			return b;
		}
	}	
}
