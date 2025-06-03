package com.yurdan.authService.service;

import com.yurdan.authService.dto.LoginRequest;
import com.yurdan.authService.model.entity.AscUser;
import com.yurdan.authService.repository.AscUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceLoginTest {

    private AscUserRepository ascUserRepository;
    private BCryptPasswordEncoder passwordEncoder;
    private TokenService tokenService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ascUserRepository = mock(AscUserRepository.class);
        passwordEncoder = mock(BCryptPasswordEncoder.class);
        tokenService = mock(TokenService.class);
        authService = new AuthService(ascUserRepository, passwordEncoder, tokenService);
    }

    @Test
    void login_validCredentials_shouldReturnToken() {
        String email = "ascUser@example.com";
        String password = "password";
        AscUser ascUser = new AscUser();
        ascUser.setEmail(email);
        ascUser.setPassword("encodedPassword");

        when(ascUserRepository.findByEmail(email)).thenReturn(ascUser);
        when(passwordEncoder.matches(password, ascUser.getPassword())).thenReturn(true);
        when(tokenService.generateToken(ascUser)).thenReturn("mocked-jwt");

        String token = authService.login(new LoginRequest(email, password));

        assertEquals("mocked-jwt", token);
        verify(tokenService).generateToken(ascUser);
    }

    @Test
    void login_invalidEmail_shouldThrow() {
        when(ascUserRepository.findByEmail("nope@example.com")).thenReturn(null);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                authService.login(new LoginRequest("nope@example.com", "pass")));

        assertEquals("Invalid email or password", ex.getMessage());
    }

    @Test
    void login_invalidPassword_shouldThrow() {
        AscUser ascUser = new AscUser();
        ascUser.setEmail("ascUser@example.com");
        ascUser.setPassword("encoded");

        when(ascUserRepository.findByEmail("ascUser@example.com")).thenReturn(ascUser);
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                authService.login(new LoginRequest("ascUser@example.com", "wrong")));

        assertEquals("Invalid email or password", ex.getMessage());
    }
}
