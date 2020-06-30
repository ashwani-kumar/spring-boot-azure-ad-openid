/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.example.demo;

import com.microsoft.azure.spring.autoconfigure.aad.AADAppRoleStatelessAuthenticationFilter;
import com.microsoft.azure.spring.autoconfigure.aad.AADAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import com.microsoft.azure.spring.autoconfigure.aad.AADAuthenticationFailureHandler;
import com.microsoft.azure.spring.autoconfigure.aad.AADOAuth2AuthorizationRequestResolver;

@EnableGlobalMethodSecurity(securedEnabled = true,
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    
	@Autowired
    private AADAuthenticationFilter aadAuthFilter;
	//@Autowired
    //private AADAppRoleStatelessAuthenticationFilter aadAuthFilter;
	//@Autowired
    //private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	System.out.println("Debugging ");
    	// Stateless session for APIs
    	http
    	.cors();
//    	http
//        .authorizeRequests()
//        .anyRequest().authenticated()
//        .and()
//        .oauth2Login()
//        .userInfoEndpoint()
//        .oidcUserService(oidcUserService);
//    	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    	http.csrf().disable();

    	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);

    	http.authorizeRequests()
    	.antMatchers("/api/**").permitAll()
    	.anyRequest().authenticated();
    	http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
    	
    	
//    	// Disable Cookies
//    	http.csrf().disable().authorizeRequests()
//    		.antMatchers("/home").permitAll()
//    		.antMatchers("/api/**").authenticated() // request matcher for authenticate user, Authenticated user can access all apis
//    		.anyRequest().permitAll()
//    		.and().httpBasic();
//
//    	// Add Active Directory filter
//    	http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
//    	http.cors();
//        http.authorizeRequests().antMatchers("/home").permitAll();
//        http.authorizeRequests().antMatchers("/api/**").authenticated();
//
//        http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//            .logoutSuccessUrl("/").deleteCookies("JSESSIONID").invalidateHttpSession(true);
//
//        http.authorizeRequests().anyRequest().permitAll();
//
//        //http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//        http.csrf().disable();
//        http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
