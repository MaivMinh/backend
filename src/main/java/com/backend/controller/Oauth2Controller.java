package com.backend.controller;

import com.backend.model.ResponseError;
import com.backend.response.ResponseData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Slf4j
@RestController
@RequestMapping(value = "/api/oauth2/google")
public class Oauth2Controller {
  private final RestTemplate restTemplate;
  private final String clientId;
  private final String clientSecret;
  private final String redirectUri;
  private final String tokenUrl;

  public Oauth2Controller(RestTemplate restTemplate, Environment env) {
    this.restTemplate = restTemplate;
    this.clientId = env.getProperty("google.client.id");
    this.clientSecret = env.getProperty("google.client.secret");
    this.redirectUri = env.getProperty("google.redirect.uri");
    this.tokenUrl = env.getProperty("google.token.url");
  }


  @RequestMapping(value = "")
  public ResponseEntity<ResponseData> handleGoogleOAuth2(@RequestParam String code) {
    ResponseEntity<String> response = null;
    try {
      // Create the token request body
      MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
      requestBody.add("code", code);
      requestBody.add("client_id", clientId);
      requestBody.add("client_secret", clientSecret);
      requestBody.add("redirect_uri", redirectUri);
      requestBody.add("grant_type", "authorization_code");

      // Set headers
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

      HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(requestBody, headers);

      // Send request to exchange authorization code for access token
      response = restTemplate.exchange(tokenUrl, HttpMethod.POST, entity, String.class);

      if (response.getStatusCode() == HttpStatus.OK) {
        log.info("OAuth2 Token received: " + response.getBody());
        //TODO: persist user data (email, name, authtype)
        System.out.println(response.getBody());
        return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Success", response.getBody()));
      } else {
        log.error("Failed to retrieve OAuth2 token: " + response.getStatusCode());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ResponseError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Failed to retrieve OAuth2 token"));
      }
    } catch (Exception e) {
      log.error("Error during OAuth2 process", e);
      Object result = response != null ? response.getBody() : null;
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .body(new ResponseData(HttpStatus.OK.value(), "Success", result));
    }
  }
}
