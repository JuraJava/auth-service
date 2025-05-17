package com.yurdan.authService.model.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "bank_user")
public class BankUser {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID uuid;

    //TODO емейл должен быть уникальный, т.к. это логин. Добавить валидацию на @email
    @Column(name = "email", nullable = false)
    private String email;

    //TODO добавить валидацию на минимальную и максимальную длину пароля
    @Column(name = "password", nullable = false)
    private String password;

    //TODO FetchType.EAGER заменить на LAZY
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "bank_user_role",
            joinColumns = @JoinColumn(name = "bank_user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private List<Role> roles;

}
