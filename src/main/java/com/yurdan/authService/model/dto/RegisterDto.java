package com.yurdan.authService.model.dto;

import com.yurdan.authService.model.entity.Role;

import java.util.List;

public record RegisterDto (String email, String password, List<Role> roles) {
}

// Возможно и без создания этого класса