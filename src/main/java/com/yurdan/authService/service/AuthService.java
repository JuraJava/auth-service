package com.yurdan.authService.service;

import com.yurdan.authService.dto.LoginRequest;
import com.yurdan.authService.model.entity.AscUser;
import com.yurdan.authService.dto.RegisterDto;
import com.yurdan.authService.repository.AscUserRepository;
import com.yurdan.authService.security.InputValidator;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Getter
    @Value("${jwt.secret}")
    private String secret;

    private final AscUserRepository ascUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public String login(LoginRequest loginRequest) {
        AscUser ascUser = ascUserRepository.findByEmail(loginRequest.getEmail());
        if (ascUser == null || !passwordEncoder.matches(loginRequest.getPassword(), ascUser.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }
        return tokenService.generateToken(ascUser);
    }

    public AscUser register(RegisterDto dto) {
        if (!InputValidator.isValidEmail(dto.email())) {
            throw new RuntimeException("Invalid email format");
        }

        if (!InputValidator.isValidPassword(dto.password())) {
            throw new RuntimeException("Password must be between 6 and 64 characters");
        }

        if (ascUserRepository.findByEmail(dto.email()) != null) {
            throw new RuntimeException("AscUser already exists");
        }

        AscUser ascUser = new AscUser();
        ascUser.setEmail(dto.email());
        ascUser.setRoles(dto.roles());
        ascUser.setPassword(passwordEncoder.encode(dto.password()));
        return ascUserRepository.save(ascUser);
    }


    public AscUser findByEmail(String email) {
        return ascUserRepository.findByEmail(email);
    }

    public Page<AscUser> findAllUsers(int page, int size) {
        if (page < 0 || size <= 0 || size > 100) {
            throw new IllegalArgumentException("Invalid pagination parameters");
        }
        return ascUserRepository.findAll(PageRequest.of(page, size));
    }

}
