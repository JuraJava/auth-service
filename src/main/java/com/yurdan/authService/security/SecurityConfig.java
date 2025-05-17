package com.yurdan.authService.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
//TODO вынести класс в пакет config
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
        http
                //TODO Отключить базовую индентификацию с помощью логина пароля и форму идентификации
                // выключить CORS и CSRF:
                // Отключить хранение состояния сессии на сервере.
                // Установить обработчик запросов для неавторизованных запросов
                .csrf(csrf -> csrf.disable()) // Отключение CSRF защиты (использовать с осторожностью)
                //TODO посмотреть на последний бин в этом классе, понять, что лучше убрать тут.
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/login").permitAll()
                        .requestMatchers("/auth/login", "/auth/register").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        // Настройка аутентификации (например, in-memory, JDBC и т.д.)

        authenticationManagerBuilder.inMemoryAuthentication()
                .withUser("user").password("{noop}password").roles("USER");

        return authenticationManagerBuilder.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        /*
         * Метод web.ignoring() сообщает Spring Security, что указанные пути или запросы
         * вообще не должны проходить через фильтры безопасности.
         * Это значит, что авторизация и аутентификация не применяются к этим запросам.
         */
        return web -> web.ignoring()
                /*
                 * анонимный класс RequestMatcher, который проверяет, должен ли данный запрос игнорироваться.
                 */
                .requestMatchers(new RequestMatcher() {
                    @Override
                    public boolean matches(HttpServletRequest request) {
                        return HttpMethod.OPTIONS.matches(request.getMethod())
                               || Stream.of(
                                "/auth/login",
                                "/auth/register",
                                "/api/swagger-ui/**",
                                "/api/swagger-config",
                                "/api",
                                "/api/doc",
                                "/metrics/**",
                                "/health/**",
                                "/info/**",
                                "/loggers/**",
                                "/internal/*"
                        ).anyMatch(pattern -> new AntPathRequestMatcher(pattern).matches(request));
                    }
                });
    }
}

