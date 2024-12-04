package com.backend.service;

import com.backend.DTOs.AccountDTO;
import com.backend.exceptions.ResourceAlreadyExistedException;
import com.backend.mapper.AccountMapper;
import com.backend.model.Account;
import com.backend.repository.AccountRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@AllArgsConstructor
public class AccountService {
  private final AccountRepo accountRepo;
  private final Environment environment;
  private final AccountMapper accountMapper;


  public AccountDTO findAccountDTOByUsername(String username) {
    return accountMapper.toDTO(accountRepo.findByUsername(username));
  }

  public Account save(Account account) {
    return accountRepo.save(account);
  }

  public Account findAccountByUsername(String username) {
    return accountRepo.findByUsername(username);
  }

  public Account findAccountByEmail(String email) {
    return accountRepo.findByEmail(email);
  }
}
