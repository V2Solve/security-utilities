package com.v2solve.app.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "v2solve.app.security.oauth2")
@Data
public class WebSecurityProperties {
	boolean enable;
	ExtendedOAuth2ClientProperties client;	
}
