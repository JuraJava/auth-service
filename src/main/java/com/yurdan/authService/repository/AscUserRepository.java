package com.yurdan.authService.repository;

import com.yurdan.authService.model.entity.AscUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AscUserRepository extends JpaRepository<AscUser, UUID> {
    AscUser findByEmail(String email);

    Page<AscUser> findAll(Pageable pageable);

}
