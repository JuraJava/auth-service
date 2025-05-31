package com.yurdan.authService.repository;

import com.yurdan.authService.model.entity.Role;
import com.yurdan.authService.model.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Object findByRoleName(RoleName roleName);

}
