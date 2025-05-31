package com.yurdan.authService.service;

import com.yurdan.authService.dto.RegisterDto;
import com.yurdan.authService.model.entity.BankUser;
import com.yurdan.authService.model.entity.Role;
import com.yurdan.authService.model.enums.RoleName;
import com.yurdan.authService.repository.BankUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceRegisterTest {

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
    void register_validInput_shouldSaveUser() {
        String email = "test@example.com";
        String password = "securePassword";
        Role role = new Role(1L, RoleName.USER);

        RegisterDto dto = new RegisterDto(email, password, Collections.singletonList(role));

        when(bankUserRepository.findByEmail(email)).thenReturn(null);
        when(passwordEncoder.encode(password)).thenReturn("encodedPassword");
        when(bankUserRepository.save(any(BankUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        BankUser result = authService.register(dto);

        assertNotNull(result);
        assertEquals(email, result.getEmail());
        assertEquals("encodedPassword", result.getPassword());
        assertEquals(1, result.getRoles().size());
        assertEquals(role.getRoleName(), result.getRoles().get(0).getRoleName());

        verify(bankUserRepository).save(any(BankUser.class));
    }

    @Test
    void register_existingUser_shouldThrow() {
        String email = "existing@example.com";
        RegisterDto dto = new RegisterDto(email, "password", Collections.emptyList());

        when(bankUserRepository.findByEmail(email)).thenReturn(new BankUser());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> authService.register(dto));
        assertEquals("User already exists", ex.getMessage());
    }

    @Test
    void register_invalidEmail_shouldThrow() {
        RegisterDto dto = new RegisterDto("invalidEmail", "password", Collections.emptyList());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> authService.register(dto));
        assertEquals("Invalid email format", ex.getMessage());
    }

    @Test
    void register_invalidPassword_shouldThrow() {
        RegisterDto dto = new RegisterDto("valid@example.com", "123", Collections.emptyList());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> authService.register(dto));
        assertEquals("Password must be between 6 and 64 characters", ex.getMessage());
    }
}
