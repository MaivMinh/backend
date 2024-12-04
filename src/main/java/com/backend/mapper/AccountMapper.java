package com.backend.mapper;

import com.backend.DTOs.AccountDTO;
import com.backend.model.Account;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface AccountMapper {
  AccountDTO toDTO(Account account);
}
