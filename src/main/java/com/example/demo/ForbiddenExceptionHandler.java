package com.example.demo;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import io.jsonwebtoken.ExpiredJwtException;

@ControllerAdvice
public class ForbiddenExceptionHandler extends ResponseEntityExceptionHandler {
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<Object> handleForbiddenException(AccessDeniedException ex, WebRequest request) {
		return new ResponseEntity<>(ex.getLocalizedMessage(), HttpStatus.FORBIDDEN);
	}
	
	@ExceptionHandler(ExpiredJwtException .class)
	public ResponseEntity<Object> handleExpiredJwtException (ExpiredJwtException ex, WebRequest request) {
		return new ResponseEntity<>(ex.getLocalizedMessage(), HttpStatus.UNAUTHORIZED);
	}
}
