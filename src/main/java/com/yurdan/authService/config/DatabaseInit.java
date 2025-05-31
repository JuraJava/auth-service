package com.yurdan.authService.config;

import com.yurdan.authService.model.entity.AscUser;
import com.yurdan.authService.model.entity.Role;
import com.yurdan.authService.model.enums.RoleName;
import com.yurdan.authService.repository.AscUserRepository;
import com.yurdan.authService.repository.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app", value = "init-data", havingValue = "true")
public class DatabaseInit {

    private final BCryptPasswordEncoder passwordEncoder;
    private final AscUserRepository ascUserRepository;
    private final RoleRepository roleRepository;

    @PostConstruct
    public void init() {
        Role role1 = Role.builder().roleName(RoleName.ADMIN).build();
        Role role2 = Role.builder().roleName(RoleName.USER).build();
        roleRepository.save(role1);
        roleRepository.save(role2);
        AscUser user1 = AscUser.builder()
                .email("admin@mail.ru")
                .password(passwordEncoder.encode("admin"))
                .roles(List.of(role1)).build();
        AscUser user2 = AscUser.builder()
                .email("user@mail.ru")
                .password(passwordEncoder.encode("user"))
                .roles(List.of(role2)).build();

        ascUserRepository.save(user1);
        ascUserRepository.save(user2);

    }
}
