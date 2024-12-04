package com.backend.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.antlr.v4.runtime.misc.NotNull;

@Entity
@Getter
@Setter
@Table(name = "accounts")
public class Account {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @NotNull
  private String username;
  @NotNull
  private String password;
  @NotNull
  private String email;
  private String name;

  @OneToOne(cascade = CascadeType.PERSIST, targetEntity = Role.class)
  @JoinColumn(name = "role_id")
  private Role role;
}
