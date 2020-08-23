package com.v2solve.app.security.config;

import lombok.Data;

/**
 * Data holder for the configuration of basic auth users.
 * @author Saurinya
 *
 */

@Data
public class BasicAuthUser 
{
	String username;
	String password;
	String roles;
}
