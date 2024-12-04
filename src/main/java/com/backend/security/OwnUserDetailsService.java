package com.backend.security;

import com.backend.model.Account;
import com.backend.service.AccountService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class OwnUserDetailsService implements UserDetailsService {
  // Class chịu trách nhiệm load thông tin của User lên hệ thống. Được sử dụng trong AuthenticationProvider.
  // -> Việc tạo thêm class này cũng chính đang triển khai nguyên lý Single-Responsibility và Open/Closed.
  private final AccountService accountService;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Account account = accountService.findAccountByUsername(username);
    if (account != null && account.getId() > 0) {
      List<GrantedAuthority> roles = List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole().getName()));
      return new User(username, account.getPassword(), roles );
    }
    throw new UsernameNotFoundException("Failed to load user by username");
  }
}
