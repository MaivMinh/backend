package com.backend.repository;

import com.backend.model.Role;
import com.backend.records.ROLE;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Integer> {
  Role findByName(ROLE name);
}
