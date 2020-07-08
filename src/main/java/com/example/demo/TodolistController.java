/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.example.demo;

import com.example.demo.model.Keys;
import com.example.demo.model.OpenIdConfigModel;
import com.microsoft.azure.spring.autoconfigure.aad.UserGroup;
import com.microsoft.azure.spring.autoconfigure.aad.UserPrincipal;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@RestController
public class TodolistController {
    private final List<TodoItem> todoList = new ArrayList<>();
    
    @Value("${azure.activedirectory.tenant-id}")
    private String tenantId;
    
    @PreAuthorize("hasRole('ROLE_pheonix')")
    @RequestMapping(value = "/api/validate", method = RequestMethod.GET)
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String authToken) {
    	String token = authToken.replace("Bearer ","");
    	String uri = "https://login.microsoftonline.com/"+tenantId+"/v2.0/.well-known/openid-configuration";
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
    		 X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
    		 PublicKey pubKeyNew = cert.getPublicKey();
    		 String signature = Jwts.parser()
  		           .setSigningKey(pubKeyNew)
  		             .parseClaimsJws(token).getSignature();
    		 return new ResponseEntity<>("OK", HttpStatus.OK);
    	} catch (Exception ex) {
    	  ex.printStackTrace();
    	  return new ResponseEntity<>(ex.getLocalizedMessage(), HttpStatus.UNAUTHORIZED);
    	}
    }
    
    public TodolistController() {
        todoList.add(0, new TodoItem(2398, "we", "whoever"));
        todoList.add(0, new TodoItem(2399, "can", "whoever"));
        todoList.add(0, new TodoItem(2400, "do", "whoever"));
        todoList.add(0, new TodoItem(2401, "anything", "whoever"));
        todoList.add(0, new TodoItem(2401, "we want", "whoever"));
    }

    @RequestMapping("/home")
    public Map<String, Object> home() {
        final Map<String, Object> model = new HashMap<>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "home");
        return model;
    }

    /**
     * HTTP GET
     */
    @PreAuthorize("hasRole('ROLE_pheonix')")
    @RequestMapping(value = "/api/todolist/{index}",
            method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<?> getTodoItem(@PathVariable("index") int index) {
        if (index > todoList.size() - 1) {
            return new ResponseEntity<>(new TodoItem(-1, "index out of range", null), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(todoList.get(index), HttpStatus.OK);
    }

    /**
     * HTTP GET ALL
     */
    @Autowired
    @PreAuthorize("hasRole('ROLE_pheonix')")
    @RequestMapping(value = "/api/todolist", method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<List<TodoItem>> getAllTodoItems() {
    	return new ResponseEntity<>(todoList, HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ROLE_pheonix')")
    @RequestMapping(value = "/api/todolist", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> addNewTodoItem(@RequestBody TodoItem item) {
        item.setID(todoList.size() + 1);
        todoList.add(todoList.size(), item);
        return new ResponseEntity<>("Entity created", HttpStatus.CREATED);
    }

    /**
     * HTTP PUT
     */
    @PreAuthorize("hasRole('pheonix')")
    @RequestMapping(value = "/api/todolist", method = RequestMethod.PUT, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> updateTodoItem(@RequestBody TodoItem item) {
        final List<TodoItem> find =
                todoList.stream().filter(i -> i.getID() == item.getID()).collect(Collectors.toList());
        if (!find.isEmpty()) {
            todoList.set(todoList.indexOf(find.get(0)), item);
            return new ResponseEntity<>("Entity is updated", HttpStatus.OK);
        }
        return new ResponseEntity<>("Entity not found", HttpStatus.OK);
    }

    /**
     * HTTP DELETE
     */
    @RequestMapping(value = "/api/todolist/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<String> deleteTodoItem(@PathVariable("id") int id,
                                                 PreAuthenticatedAuthenticationToken authToken) {
        final UserPrincipal current = (UserPrincipal) authToken.getPrincipal();

        if (current.isMemberOf(
                new UserGroup("835544af-8a59-4608-90aa-9167bc1b3399", "pheonix"))) {
            final List<TodoItem> find = todoList.stream().filter(i -> i.getID() == id).collect(Collectors.toList());
            if (!find.isEmpty()) {
                todoList.remove(todoList.indexOf(find.get(0)));
                return new ResponseEntity<>("OK", HttpStatus.OK);
            }
            return new ResponseEntity<>("Entity not found", HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Access is denied", HttpStatus.OK);
        }

    }
}
