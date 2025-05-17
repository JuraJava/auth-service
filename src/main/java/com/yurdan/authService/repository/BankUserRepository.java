package com.yurdan.authService.repository;

import com.yurdan.authService.model.entity.BankUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface BankUserRepository extends JpaRepository<BankUser, UUID> {
    BankUser findByEmail(String email);

    Page<BankUser> findAll(Pageable pageable);

}
