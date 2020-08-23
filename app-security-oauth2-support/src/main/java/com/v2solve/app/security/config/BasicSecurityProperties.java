package com.v2solve.app.security.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

/**
 * This class maps the spring configuration properties for setting up the basic security
 * @author Saurinya
 *
 */

@Data
@Configuration
@ConfigurationProperties(prefix = "v2solve.app.security.basic")
public class BasicSecurityProperties 
{
	/**
	 * Configuration for basic security should only be enabled if this is true..
	 */
	boolean enable;
	
	/**
	 * The realm for the users.
	 */
	String  realm;
	
	/**
	 * List of users configured in the configuration.
	 */
	List<BasicAuthUser> users;
}