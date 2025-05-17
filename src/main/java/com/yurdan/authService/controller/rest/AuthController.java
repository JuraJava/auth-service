package com.yurdan.authService.controller.rest;

import com.yurdan.authService.model.LoginRequest;
import com.yurdan.authService.model.dto.RegisterDto;
import com.yurdan.authService.model.entity.BankUser;
import com.yurdan.authService.repository.BankUserRepository;
import com.yurdan.authService.service.AuthService;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final BankUserRepository bankUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        try {
            return ResponseEntity.ok(authService.login(loginRequest));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid email or password");
        }
    }

    @PostMapping("/register")
    //TODO убрать зависимость от Entity из контроллера, не использовать Entity для передачи данных, вместо него использовать DTO
    public ResponseEntity<?> register(@RequestBody BankUser bankUser) {
        //TODO вынести зависимость от репозитория из контроллера в сервис-слой
        if (bankUserRepository.findByEmail(bankUser.getEmail()) != null) {
            return ResponseEntity.badRequest().body("User already exists");
        }
        //TODO вынести зависимость от passwordEncoder из контроллера в сервис-слой
        bankUser.setPassword(passwordEncoder.encode(bankUser.getPassword()));
        BankUser savedUser = bankUserRepository.save(bankUser);
        return ResponseEntity.ok(savedUser);
    }

    //TODO убрать все закомментированные строки.
// // Этот метод использовался  тогда, когда использовался RegisterDto
//    @PostMapping("/register")
//    public ResponseEntity<?> register(@RequestBody RegisterDto registerDto) {
//        if (bankUserRepository.findByEmail(registerDto.email()) != null) {
//            return ResponseEntity.badRequest().body("User already exists");
//        }
//        BankUser bankUser = new BankUser();
//        bankUser.setEmail(registerDto.email());
//        bankUser.setPassword(passwordEncoder.encode(registerDto.password()));
//
////        bankUser.setRoles(List.of(new Role(1L, Role.RoleName.USER))); // Добавлялся только USER ?
//
//        bankUser.setRoles(registerDto.roles());
//
//        BankUser savedUser = bankUserRepository.save(bankUser);
//        return ResponseEntity.ok(savedUser);
//    }


    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    public ResponseEntity<?> getAllUsers(Principal principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        //TODO вынести зависимость от репозитория из контроллера в сервис-слой
        BankUser bankUser = bankUserRepository.findByEmail(principal.getName());

        if (bankUser == null || bankUser.getRoles().stream().noneMatch(role -> role.getRoleName().name().equals("ADMIN"))) {
            return ResponseEntity.status(403).body("Access denied");
        }
        //TODO вынести зависимость от репозитория из контроллера в сервис-слой
        //TODO Проерять, верные ли параметры передаются в запросе. Например, если приедут отрицательные числа, что тогда?
        Page<BankUser> users = bankUserRepository.findAll(PageRequest.of(page, size));
        return ResponseEntity.ok(users);
    }

    //TODO убрать все закомментированные строки.
//    // Этот метод перенести в отдельный класс
//    // 🔍 Валидация токена (без Redis)
//    @GetMapping("/validate")
//    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            return ResponseEntity.status(401).body("Missing or invalid Authorization header");
//        }
//
//        String token = authHeader.replace("Bearer ", "");
//
//        try {
//            Jws<Claims> claims = Jwts.parser()
//                    .setSigningKey(authService.getSecret().getBytes())
//                    .parseClaimsJws(token);
//
//            return ResponseEntity.ok(claims.getBody());
//        } catch (ExpiredJwtException e) {
//            return ResponseEntity.status(401).body("Token expired");
//        } catch (JwtException e) {
//            return ResponseEntity.status(401).body("Invalid token");
//        }
//    }
}

