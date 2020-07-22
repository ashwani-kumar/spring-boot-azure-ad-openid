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
		} catch (Exception ex) {
			ex.printStackTrace();
			SecurityContextHolder.clearContext();
		}

		chain.doFilter(request, response);
	}

}