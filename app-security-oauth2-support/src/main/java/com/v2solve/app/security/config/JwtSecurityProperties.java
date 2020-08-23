package com.v2solve.app.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "v2solve.app.security.jwt")
@Data
public class JwtSecurityProperties {
	boolean enable;
	ExtendedOAuth2ClientProperties client;
}
