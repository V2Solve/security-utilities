package com.v2solve.app.security.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.NoArgsConstructor;

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
	 * Jdbc Authentication if required.
	 */
	JDBCAuthSetup jdbc;
	
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
	
	
	@Data
	@NoArgsConstructor
	static class JDBCAuthSetup
	{	
		/**
		 * If true it will setup JDBC Authentication
		 */
		boolean enable;
		
		/**
		 * Name of the data source bean
		 * if not provided, will try the first data source bean that is available in the environment.
		 */
		String dataSourceBeanName;
		
		String usersByUsernameQuery;

		String authoritiesByUsernameQuery;
	}
}