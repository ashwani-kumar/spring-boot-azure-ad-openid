/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.example.demo;

import com.microsoft.azure.spring.autoconfigure.aad.AADAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableGlobalMethodSecurity(securedEnabled = true,
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    
	@Autowired
    private AADAuthenticationFilter aadAuthFilter;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	System.out.println("Debugging ");
    	// Stateless session for APIs
//    	http
//    	.cors();
//
//    	http.csrf().disable();
//
//    	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
//
//    	http.authorizeRequests()
//    	.antMatchers("/home").permitAll()
//    	.antMatchers("/api/**").authenticated()
//    	.anyRequest().authenticated();
//    	http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
    	
    	http.cors();
        http.authorizeRequests().antMatchers("/home").permitAll();
        http.authorizeRequests().antMatchers("/api/**").authenticated();

        http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/").deleteCookies("JSESSIONID").invalidateHttpSession(true);

        http.authorizeRequests().anyRequest().permitAll();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        //http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.csrf().disable();
        http.addFilterAfter(new JwtTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
        	.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
