package com.yurdan.authService.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yurdan.authService.model.enums.RoleName;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "roles")
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "role_name", nullable = false, unique = true)
    private RoleName roleName;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "roles")
    private List<AscUser> ascUsers;

    @Override
    public String getAuthority() {
        return roleName.toString();
    }
}


