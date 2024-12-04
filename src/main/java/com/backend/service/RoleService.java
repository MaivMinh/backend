package com.backend.service;

import com.backend.model.Role;
import com.backend.records.ROLE;
import com.backend.repository.RoleRepo;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class RoleService {
  private final RoleRepo roleRepo;

  public Role findByRoleName(ROLE name) {
    return roleRepo.findByName(name);
  }
}
