package com.yurdan.authService.service;

import com.yurdan.authService.model.entity.AscUser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String KEY_UUID = "uuid";
    private static final String KEY_EMAIL = "email";
    private static final String KEY_ROLES = "roles";
//    private static final long EXPIRATION_TIME_MS = 3600_000; // 1 час
    private static final long EXPIRATION_TIME_MS = 360_000; // 6 мин.
    @Value("${jwt.secret}")
    private String secret;

    private SecretKey secretKey;

    @PostConstruct
    public void initKey() {
        this.secretKey = new SecretKeySpec(secret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateToken(AscUser ascUser) {
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put(KEY_UUID, ascUser.getId().toString());
            payload.put(KEY_EMAIL, ascUser.getEmail());
            payload.put(KEY_ROLES, ascUser.getRoles().stream()
                    .map(r -> r.getRoleName().name()).toList());

            return Jwts.builder()
                    .setClaims(payload)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_MS))
                    .signWith(secretKey)
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException("Token generation failed", e);
        }
    }
}

