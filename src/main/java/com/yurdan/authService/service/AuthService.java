package com.yurdan.authService.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yurdan.authService.model.LoginRequest;
import com.yurdan.authService.model.entity.BankUser;
import com.yurdan.authService.repository.BankUserRepository;
import io.jsonwebtoken.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Getter
    @Value("${jwt.secret}")
    private String secret;

    private final BankUserRepository bankUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public String login(LoginRequest loginRequest) {
        BankUser bankUser = bankUserRepository.findByEmail(loginRequest.getEmail());
        if (bankUser == null || !passwordEncoder.matches(loginRequest.getPassword(), bankUser.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        return generateToken(bankUser);
    }

    //TODO вынести генерацию токена в отдельный сервис
    private String generateToken(BankUser bankUser) {
        try {
            Map<String, Object> payload = new HashMap<>();
//            TODO вынести ключи в константы. А еще лучше сделать не мапу, а ДТО
            payload.put("uuid", bankUser.getUuid().toString());
            payload.put("email", bankUser.getEmail());
            payload.put("roles", bankUser.getRoles().stream()
                    .map(role -> role.getRoleName().name())
                    .collect(Collectors.toList()));

            String payloadJson = new ObjectMapper().writeValueAsString(payload);

            return Jwts.builder()
                    .setPayload(payloadJson)
//                    .setIssuedAt(new Date())
//                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                    .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException("Token generation failed", e);
        }
    }

    //TODO убрать все закомментированные строки.
// // Этот метод желательно перенести в отдельный класс
//    public boolean isAdmin(String token) {
//        try {
//            String[] chunks = token.split("\\.");
//            if (chunks.length < 2) throw new IllegalArgumentException("Invalid token");
//
//            String payloadJson = new String(Base64.getDecoder().decode(chunks[1]));
//            ObjectMapper mapper = new ObjectMapper();
//            Map<String, Object> payload = mapper.readValue(payloadJson, Map.class);
//
//            List<?> roles = (List<?>) payload.get("roles");
//            return roles.contains("ADMIN");
//        } catch (Exception e) {
//            return false;
//        }
//    }
}
