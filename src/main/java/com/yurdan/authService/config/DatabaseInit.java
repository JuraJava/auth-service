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
        Role role3 = Role.builder().roleName(RoleName.RECEIVER).build();
        Role role4 = Role.builder().roleName(RoleName.ENGINEER).build();
        Role role5 = Role.builder().roleName(RoleName.ADMINISTRATOR).build();
        Role role7 = Role.builder().roleName(RoleName.STOREKEEPER).build();
        Role role6 = Role.builder().roleName(RoleName.DIRECTOR).build();
        roleRepository.save(role1);
        roleRepository.save(role2);
        roleRepository.save(role3);
        roleRepository.save(role4);
        roleRepository.save(role5);
        roleRepository.save(role6);
        roleRepository.save(role7);

        AscUser user1 = AscUser.builder()
                .email("admin@mail.ru")
                .password(passwordEncoder.encode("admin"))
                .roles(List.of(role1)).build();
        AscUser user2 = AscUser.builder()
                .email("user@mail.ru")
                .password(passwordEncoder.encode("user"))
                .roles(List.of(role2)).build();
        AscUser user3 = AscUser.builder()
                .email("receiver@mail.ru")
                .password(passwordEncoder.encode("receiver"))
                .roles(List.of(role3)).build();
        AscUser user4 = AscUser.builder()
                .email("engineer@mail.ru")
                .password(passwordEncoder.encode("engineer"))
                .roles(List.of(role4)).build();
        AscUser user5 = AscUser.builder()
                .email("administrator@mail.ru")
                .password(passwordEncoder.encode("administrator"))
                .roles(List.of(role5)).build();
        AscUser user6 = AscUser.builder()
                .email("storekeeper@mail.ru")
                .password(passwordEncoder.encode("storekeeper"))
                .roles(List.of(role6)).build();
        AscUser user7 = AscUser.builder()
                .email("director@mail.ru")
                .password(passwordEncoder.encode("director"))
                .roles(List.of(role7)).build();

        ascUserRepository.save(user1);
        ascUserRepository.save(user2);
        ascUserRepository.save(user3);
        ascUserRepository.save(user4);
        ascUserRepository.save(user5);
        ascUserRepository.save(user6);
        ascUserRepository.save(user7);

    }
}
