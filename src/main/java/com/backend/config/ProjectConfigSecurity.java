package com.backend.config;

import com.backend.security.CustomAccessDeniedHandler;
import com.backend.security.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class ProjectConfigSecurity {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.csrf(AbstractHttpConfigurer::disable);
    http
            .authorizeHttpRequests(config -> config
                    .requestMatchers(
                            "/api/v1/auth/**").permitAll()
                    .anyRequest().authenticated());
    http.httpBasic(config -> config.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
    http.exceptionHandling(config -> config.accessDeniedHandler(new CustomAccessDeniedHandler()));
    return http.build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*").allowCredentials(false).exposedHeaders("*").allowedMethods("*");
      }
    };
  }
}
