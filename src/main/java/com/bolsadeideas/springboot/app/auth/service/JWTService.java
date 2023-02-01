package com.bolsadeideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;

import io.jsonwebtoken.Claims;

public interface JWTService {

	public String create(Authentication auth) throws IOException;

	public boolean validate(String token);

	public Claims getClaims(String token);

	public String getUsername(String token);

	public Collection<? extends GrantedAuthority> getRoles(String token) throws StreamReadException, DatabindException, IOException;

	public String resolve(String token);
}
