package com.yurdan.authService.security;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class JwtAuthentication extends AbstractAuthenticationToken {

    private final UUID uuid;
    private final String email;

    public JwtAuthentication(UUID uuid, String email, List<SimpleGrantedAuthority> authorities) {
        super(authorities);
        this.uuid = uuid;
        this.email = email;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return email;
    }

    public UUID getUuid() {
        return uuid;
    }

    public static JwtAuthentication fromPayload(Map<String, Object> payload) {
        UUID uuid = UUID.fromString(payload.get("uuid").toString());
        String email = payload.get("email").toString();
        List<String> roles = (List<String>) payload.get("roles");
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return new JwtAuthentication(uuid, email, authorities);
    }
}
