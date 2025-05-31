package com.yurdan.authService.service;

import com.yurdan.authService.dto.LoginRequest;
import com.yurdan.authService.model.entity.BankUser;
import com.yurdan.authService.repository.BankUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceLoginTest {

    private BankUserRepository bankUserRepository;
    private BCryptPasswordEncoder passwordEncoder;
    private TokenService tokenService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        bankUserRepository = mock(BankUserRepository.class);
        passwordEncoder = mock(BCryptPasswordEncoder.class);
        tokenService = mock(TokenService.class);
        authService = new AuthService(bankUserRepository, passwordEncoder, tokenService);
    }

    @Test
    void login_validCredentials_shouldReturnToken() {
        String email = "user@example.com";
        String password = "password";
        BankUser user = new BankUser();
        user.setEmail(email);
        user.setPassword("encodedPassword");

        when(bankUserRepository.findByEmail(email)).thenReturn(user);
        when(passwordEncoder.matches(password, user.getPassword())).thenReturn(true);
        when(tokenService.generateToken(user)).thenReturn("mocked-jwt");

        String token = authService.login(new LoginRequest(email, password));

        assertEquals("mocked-jwt", token);
        verify(tokenService).generateToken(user);
    }

    @Test
    void login_invalidEmail_shouldThrow() {
        when(bankUserRepository.findByEmail("nope@example.com")).thenReturn(null);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                authService.login(new LoginRequest("nope@example.com", "pass")));

        assertEquals("Invalid email or password", ex.getMessage());
    }

    @Test
    void login_invalidPassword_shouldThrow() {
        BankUser user = new BankUser();
        user.setEmail("user@example.com");
        user.setPassword("encoded");

        when(bankUserRepository.findByEmail("user@example.com")).thenReturn(user);
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                authService.login(new LoginRequest("user@example.com", "wrong")));

        assertEquals("Invalid email or password", ex.getMessage());
    }
}
