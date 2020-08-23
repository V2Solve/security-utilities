package com.v2solve.app.security.config;


import com.v2solve.app.security.utility.oauth2.ExtendedOAuth2ClientProperties;
import lombok.Data;


@Data
public class OAuth2SecurityProperties {
	boolean enable;
	ExtendedOAuth2ClientProperties client;
}
