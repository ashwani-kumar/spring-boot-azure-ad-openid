package com.example.demo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.model.Keys;
import com.example.demo.model.OpenIdConfigModel;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {
	private String tenantId="40f1e5a5-359b-4b1c-8a2d-7b80162497ec";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		// 1. get the authentication header. Tokens are supposed to be passed in the
		// authentication header
		String header = request.getHeader("Authorization");

		// 2. validate the header and check the prefix
		if (header == null || !header.startsWith("Bearer")) {
			chain.doFilter(request, response); // If not valid, go to the next filter.
			return;
		}

		// If there is no token provided and hence the user won't be authenticated.
		// It's Ok. Maybe the user accessing a public path or asking for a token.

		// All secured paths that needs a token are already defined and secured in
		// config class.
		// And If user tried to access without access token, then he won't be
		// authenticated and an exception will be thrown.

		// 3. Get the token
		String token = header.replace("Bearer ", "");
		System.out.println(token);
		String uri = "https://login.microsoftonline.com/" + tenantId + "/v2.0/.well-known/openid-configuration";
		RestTemplate restTemplate = new RestTemplate();
		OpenIdConfigModel config = restTemplate.getForObject(uri, OpenIdConfigModel.class);
		String keysUri = config.getJwksUri();
		RestTemplate restTemplateKeys = new RestTemplate();
		Keys result = restTemplateKeys.getForObject(keysUri, Keys.class);

		try {
			String x5c = result.getKeys().get(0).getX5c().get(0);
			byte[] certChain = Base64.getDecoder().decode(x5c);
			InputStream in = new ByteArrayInputStream(certChain);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
			PublicKey pubKeyNew = cert.getPublicKey();
			Claims claims = Jwts.parser().setSigningKey(pubKeyNew).parseClaimsJws(token).getBody();

			String username = claims.getSubject();
			if (username != null) {
				@SuppressWarnings("unchecked")
				List<String> authorities = (List<String>) claims.get("authorities");

				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null,
						authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			SecurityContextHolder.clearContext();
		}

//		try {	// exceptions might be thrown in creating the claims if for example the token is expired
//			
//			// 4. Validate the token
//			Claims claims = Jwts.parser()
//					.setSigningKey(jwtConfig.getSecret().getBytes())
//					.parseClaimsJws(token)
//					.getBody();
//			
//			String username = claims.getSubject();
//			if(username != null) {
//				@SuppressWarnings("unchecked")
//				List<String> authorities = (List<String>) claims.get("authorities");
//				
//				// 5. Create auth object
//				// UsernamePasswordAuthenticationToken: A built-in object, used by spring to represent the current authenticated / being authenticated user.
//				// It needs a list of authorities, which has type of GrantedAuthority interface, where SimpleGrantedAuthority is an implementation of that interface
//				 UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
//								 username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
//				 
//				 // 6. Authenticate the user
//				 // Now, user is authenticated
//				 SecurityContextHolder.getContext().setAuthentication(auth);
//			}
//			
//		} catch (Exception e) {
//			// In case of failure. Make sure it's clear; so guarantee user won't be authenticated
//			SecurityContextHolder.clearContext();
//		}
//		
		// go to the next filter in the filter chain
		chain.doFilter(request, response);
	}

}