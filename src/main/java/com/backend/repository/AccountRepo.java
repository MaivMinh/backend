package com.backend.repository;

import com.backend.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepo extends JpaRepository<Account, Integer> {
  Account findByUsername(String username);
  Account findByEmail(String email);
}
