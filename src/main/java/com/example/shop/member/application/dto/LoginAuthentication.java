package com.example.shop.member.application.dto;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class LoginAuthentication extends UsernamePasswordAuthenticationToken {
    public LoginAuthentication(Object principal, @Nullable Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
    public LoginAuthentication(Object principal, @Nullable Object credentials) {
        super(principal, credentials);
    }
}
