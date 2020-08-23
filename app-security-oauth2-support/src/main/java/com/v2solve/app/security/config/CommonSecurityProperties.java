package com.v2solve.app.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix="v2solve.app.security")
@Data
public class CommonSecurityProperties {

	/**
	 * Global flag to disable all security
	 */
	boolean disable;
	
	String xframeOption;
	String [] authwhitelist;
	CorsConfiguration cors;
}
