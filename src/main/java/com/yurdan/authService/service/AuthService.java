package com.yurdan.authService.service;

import com.yurdan.authService.dto.LoginRequest;
import com.yurdan.authService.model.entity.BankUser;
import com.yurdan.authService.dto.RegisterDto;
import com.yurdan.authService.repository.BankUserRepository;
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

    private final BankUserRepository bankUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public String login(LoginRequest loginRequest) {
        BankUser bankUser = bankUserRepository.findByEmail(loginRequest.getEmail());
        if (bankUser == null || !passwordEncoder.matches(loginRequest.getPassword(), bankUser.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }
        return tokenService.generateToken(bankUser);
    }

    public BankUser register(RegisterDto dto) {
        if (!InputValidator.isValidEmail(dto.email())) {
            throw new RuntimeException("Invalid email format");
        }

        if (!InputValidator.isValidPassword(dto.password())) {
            throw new RuntimeException("Password must be between 6 and 64 characters");
        }

        if (bankUserRepository.findByEmail(dto.email()) != null) {
            throw new RuntimeException("User already exists");
        }

        BankUser user = new BankUser();
        user.setEmail(dto.email());
        user.setRoles(dto.roles());
        user.setPassword(passwordEncoder.encode(dto.password()));
        return bankUserRepository.save(user);
    }


    public BankUser findByEmail(String email) {
        return bankUserRepository.findByEmail(email);
    }

    public Page<BankUser> findAllUsers(int page, int size) {
        if (page < 0 || size <= 0 || size > 100) {
            throw new IllegalArgumentException("Invalid pagination parameters");
        }
        return bankUserRepository.findAll(PageRequest.of(page, size));
    }

}
