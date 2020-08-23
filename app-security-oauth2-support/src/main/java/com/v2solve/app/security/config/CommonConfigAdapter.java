package com.v2solve.app.security.config;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CommonConfigAdapter extends WebSecurityConfigurerAdapter 
{
    CorsConfigurationSource corsConfigurationSource(CommonSecurityProperties csp) 
    {
    	if (csp == null || csp.getCors() == null)
    		return null;
    	
        CorsConfigurationSource ccs = new CorsConfigurationSource() 
        {
			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) 
			{
		        return csp.getCors();
			}
		};
		
		return ccs;
    }
    
    
    void setXframeOptions (HttpSecurity http, CommonSecurityProperties csp) 
    throws Exception
    {
    	if (csp != null)
    	{
    		String xframeOption = csp.getXframeOption();
    		if (xframeOption != null)
    		{
    			if (xframeOption.equalsIgnoreCase("deny"))
    			{
    				log.info("FrameOptions: deny");
    				http.headers().frameOptions().deny();
    			}
    			else if (xframeOption.equalsIgnoreCase("same-origin") || xframeOption.equalsIgnoreCase("sameorigin"))
    			{
    				log.info("FrameOptions: same-origin");
    				http.headers().frameOptions().sameOrigin();
    			}
    			else
    			{
    				log.info("FrameOptions: disabled");
    				http.headers().frameOptions().disable();	// Default..
    			}
    		}
    		else
    		{
    			log.info("FrameOptions: disabled");
    			http.headers().frameOptions().disable();	// Default..
    		}
    	}
    	else
    	{
    		log.info("FrameOptions: disabled");
    		http.headers().frameOptions().disable();	// Default..
    	}
    }
    
    
    void setCommonConfiguration (HttpSecurity http, CommonSecurityProperties csp)
    throws Exception
    {
    	setXframeOptions(http, csp);
    	CorsConfigurationSource ccs = corsConfigurationSource(csp);
    	
    	if (ccs != null)
    	{
    		log.info("CorsConfiguration: " + csp.getCors());
    		http.cors().configurationSource(ccs);
    	}
    	else
    	{
    		log.info("CorsConfiguration: disabled");
    		http.cors().disable();
    	}
    	
    	http.csrf().disable();
    	// log.info("CSRFConfiguration: CookieCsrfTokenRepository.withHttpOnlyFalse()");
    	// http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
    
    void setCommonAuthPattern (HttpSecurity http, CommonSecurityProperties csp) 
    throws Exception
    {
    	String [] authWhiteList = null;
    	
    	if (csp != null)
    		authWhiteList = csp.getAuthwhitelist(); 
	    
    	
    	if (authWhiteList != null)
    	{
    		log.info("AuthenticationWhiteList: " + Arrays.asList(authWhiteList));
	    	http.antMatcher("/**")
	    	    .authorizeRequests()
	    	    .antMatchers(authWhiteList)
		        .permitAll();
    	}
    	
    	http
	      .antMatcher("/**")
	      .authorizeRequests()
	      .anyRequest()
	      .authenticated();
    	
    }
}