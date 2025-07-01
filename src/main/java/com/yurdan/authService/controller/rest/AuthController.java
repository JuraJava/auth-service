package com.yurdan.authService.controller.rest;

import com.yurdan.authService.dto.LoginRequest;
import com.yurdan.authService.dto.RegisterDto;
import com.yurdan.authService.model.entity.AscUser;
import com.yurdan.authService.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        try {
            return ResponseEntity.ok(authService.login(loginRequest));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid email or password");
        }
    }
//    @PreAuthorize("hasAnyAuthority('ADMINISTRATOR', 'RECEIVER')")
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDto registerDto) {
        try {
            AscUser savedAscUser = authService.register(registerDto);
            return ResponseEntity.ok(savedAscUser);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers(Principal principal,
                                         @RequestParam(defaultValue = "0") int page,
                                         @RequestParam(defaultValue = "10") int size) {

        AscUser requester = authService.findByEmail(principal.getName());

        if (requester == null || requester.getRoles().stream()
                .noneMatch(role -> role.getRoleName().name().equals("ADMIN"))) {
            return ResponseEntity.status(403).body("Access denied");
        }

        Page<AscUser> users = authService.findAllUsers(page, size);
        return ResponseEntity.ok(users);
    }

}
