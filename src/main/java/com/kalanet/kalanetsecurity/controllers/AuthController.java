package com.kalanet.kalanetsecurity.controllers;

import com.kalanet.kalanetsecurity.model.AuthenticationResponse;
import com.kalanet.kalanetsecurity.model.Client;
import com.kalanet.kalanetsecurity.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping(path = "/register", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<AuthenticationResponse> register( Client client) {
        return ResponseEntity.ok(authenticationService.register(client));
    }

  /*  @PostMapping(path = "/login", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<AuthenticationResponse> login(Client client) {
        return ResponseEntity.ok(authenticationService.authenticate(client));
    }*/

    @PostMapping(value = "/login", consumes = "application/x-www-form-urlencoded")
    public String login(Client client) {
        authenticationService.authenticate(client);
        return "redirect:/admin";
    }


}
