# app-security-oauth2-support

>If you find this library useful kindly consider donating some money for encouraging more work and development.  



<form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
<input type="hidden" name="cmd" value="_donations" />
<input type="hidden" name="business" value="UF8VXYJWHRZQE" />
<input type="hidden" name="item_name" value="To help fund library development" />
<input type="hidden" name="currency_code" value="USD" />
<input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif" border="0" name="submit" title="PayPal - The safer, easier way to pay online!" alt="Donate with PayPal button" />
<img alt="" border="0" src="https://www.paypal.com/en_US/i/scr/pixel.gif" width="1" height="1" />
</form>  

---


## Features

* Disabling Security in Spring Boot
* Basic Auth style authentication (user list, as well as database driven)
* OpenId connect Authorization Code flow for Single Sign On.
* Jwt style protection for your application (Multiple Jwt providers/checks)
* Configuration support for Angular Style/Single Page/JavaScript style Application.



## Quick Start

The way to quickly start using the library is illustrated in the quick steps sequence.



**STEP 1**

Create a Spring Boot Maven application and in your pom include the library as a dependency.


```
    <dependency>	
        <groupId>com.v2solve.app.security</groupId>
        <artifactId>app-security-oauth2-support</artifactId>
            <!--  Always check for latest version in mvn central -->
        <version>233.1.0.RELEASE</version>
	</dependency>
```
---

**STEP 2**

Then in your spring boot application config, enable the security configuration.

```
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.v2solve.app.security.config.EnableSecurity;

/**
 * Main Spring boot class for the application
 * @author Saurinya
 *
 */
@EnableSecurity
@SpringBootApplication
public class Application 
{
	/**
	 * Standard run method.
	 * @param args
	 */
	public static void main (final String args [])
	{
		SpringApplication.run(Application.class, args);
	}
	
}
```
---
**STEP 3**  

Then configure the security settings in your application.yml file as shown below. You need different configurations depending on what security you want to enable. There are 4 supported configurations at present.
* Disabling the security
* Configuring it for SSO using OpenID provider (AuthCodeFlow)
* Configuring it to Protect your endpoints using Jwt
* Configuring the application to use Basic Authentication

Each of the configurations are briefly explained in points 1 through 4

1. **Disabling the security**

   This is a simple configuration as shown below.

```
v2solve:
  app:
    security:
      disable: true

```
The above will essentially configure the spring web security to allow all endpoints to be accessed without authentication.


2. **Enable Authorization_Code flow type of OpenID / OAuth2 style authentication**  
   
   A sample configuration for this kind of a setup is as shown below

```
v2solve:    
  app:
    security:
      authwhitelist: "/oidc-support**"
      oauth2:
        enable: true
        client:
          registration:
            okta:
              provider: "https://dev-869380.okta.com"
              client-id: "xxxxxx"
              client-secret: "xxxxx"
              client-name: Okta
              scope:
              - email
              - profile
              - openid
          provider:
            okta:
              user-name-attribute: email
              issuer-uri: "https://dev-869380.okta.com"


```

In the above configuration a OAuth2Provider is setup to be used as the authentication provider. All URL except for the comma delimited patterns of the property **authwhitelist:**  are protected. The authwhitelist patterns allow unauthenticated access.

This documentation does not seek to educate the user on OAuth so if these properties are not known to you, then you can quickly read about open id authentication on the internet. Once you understand OpenId authentication and authorization flows and mechanisms, the above properties will be understood.

>Note Multiple providers can be configured. They will be distinguished with their names.


---


3. **Protect your WebEndPoints using JSON Web Token Style protection by accepting tokens from multiple providers (Jwt Style)**

a Sample configuration to protect the app by Jwt Style web tokens is provided below.

```
v2solve:    
  app:
    security:
      authwhitelist: "/oidc-support**"
      jwt:
        enable: true
        client:
          registration:
            okta:
              provider: "https://dev-869380.okta.com"
          provider-extension:
            okta:
              claim-checks:
                aud:
                  allowed-values:
                  - xyz 
                  - abc
                acr:
                  allowed-values:
                  - 123
                  - 456


```

The above configuration will protect all URL other than the comma delimited **authwhitelist** property.  The _**provider-extension**_ section is a custom addition by the library to allow for checking values inside claims so that even though the Jwt token may have been issued by the provider, it will not allow verification unless one of those claims are a part of the token.

> Note: Multiple registrations (providers) can be setup here. Meaning your application can accept tokens from say microsoft as well as facebook.

---


4. Protect your application using basic auth style protection where a user name password is required to access the applicaition. This has two flavors..
   
   * Users are in the application.yml along with their passwords.
   * Users are in a database table(s) along with their roles

In this configuration you can setup the application be secured using basic auth style of protection.  The basic auth style is oldest form of protection and it simply means that a correct userid password must be passed to the application. 

The list of users can either be in the application properties, OR it can be in a database. If the users are in a database then additional configuration is required under the basic security configuration. The sample configuration below contains both such entrys..


<span style="color: green; font-size: 10">

```
v2solve:    
  app:
    security:
      authwhitelist: "/someurl**"
      basic:
        enable: true
        jdbc:
          enable: true
          dataSourceBeanName: <provide the name of the datasource bean configured in the app>
          usersByUsernameQuery: "select name as username,user_password as password,enabled from basic_auth_clients where name = ?"
          authoritiesByUsernameQuery: "select name as username,'ADMIN' as authority from basic_auth_clients where name = ?"
        realm: v2solve
        users:
          - username: user1 
            password: password
            roles: somerole
          - username: user2
            password: someotherpassword
            roles: somerole

```

</span>

In the above configuration both basic security using a user list in the application yml file (property file) as well as users in the database will be setup. 

>Note: Enabling for jdbc requires that database tables be setup in such a way that the two queries above are satisfied. This is a minimum requirement. Also a datasource bean must point to the database. If you provide a name of datasource bean (dataSourceBeanName property) then that is the one that will be used, otherwise the library will attempt to use the default datasource. If no datasource is setup, the library will error during configuration.



