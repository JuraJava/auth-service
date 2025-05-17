package com.yurdan.authService.security;

import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
//TODO вынести в константу Authorization, Bearer и "".
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.replace("Bearer ", "");
            try {
                if (jwtUtils.validateToken(token)) {
                    //TODO вытащить сразу всю инфу, а не по частям. Тут вызывается дважды один и тот же метод getPayload()
                    //TODO Если записывал в токен Мапу, то мапу и доставай.
                    String email = jwtUtils.getEmailFromToken(token);
                    List<String> roles = jwtUtils.getRolesFromToken(token);

                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();
                    //TODO Использовать JwtAuthentication вместо UsernamePasswordAuthenticationToken
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(email, null, authorities);

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (JwtException e) {
                //TODO логирование
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        filterChain.doFilter(request, response);
        //TODO если на каком то этапе авторизация не прошла, нужно почистить SecurityContext.
        //TODO Не увидел, где проверяется, что токен не просрочен.
    }
}
