package com.yurdan.authService.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    @Value("${jwt.secret}")
    private String secret;
// Этот метод ранее был расположен в классе AuthController
    public boolean validateToken(String token) {
        try {
            //TODO заменить deprecated parser на parserBuilder
            Jwts.parser()
                    //TODO подготовить secret на этапе создания класса, исключив постоянные лишние вызовы.
                    //TODO использовать имплементацию "Key" из перегруженного метода setSigningKey(Key var1); Например SecretKey
                    .setSigningKey(secret.getBytes())
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            //TODO логирование
            return false;
        }
    }

    public String getEmailFromToken(String token) {
        return (String) getPayload(token).get("email");
    }

    public List<String> getRolesFromToken(String token) {
        Object rolesObj = getPayload(token).get("roles");
        if (rolesObj instanceof List<?> roles) {
            return roles.stream()
                    .map(Object::toString)
                    .toList();
        }
        return Collections.emptyList();
    }
// Ранее эта логика была в методе isAdmin() в классе AuthService
    private Map<String, Object> getPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid token");

        String payloadJson = new String(Base64.getDecoder().decode(parts[1]));
        try {
            return new ObjectMapper().readValue(payloadJson, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new RuntimeException("Invalid token payload", e);
        }
    }
}

