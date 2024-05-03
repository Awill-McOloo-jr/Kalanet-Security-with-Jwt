package com.kalanet.kalanetsecurity.services;

import com.kalanet.kalanetsecurity.model.AuthenticationResponse;
import com.kalanet.kalanetsecurity.model.Client;
import com.kalanet.kalanetsecurity.repository.ClientRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private PasswordEncoder passwordEncoder;
    private ClientRepository clientRepository;
    private JwtService jwtService;

    private AuthenticationManager authenticationManager;

    public AuthenticationService(PasswordEncoder passwordEncoder, ClientRepository clientRepository, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.passwordEncoder = passwordEncoder;
        this.clientRepository = clientRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register (Client client) {
        Client myClient = new Client();
        myClient.setUsername(client.getUsername());
        myClient.setPassword(passwordEncoder.encode(client.getPassword()));
        myClient.setRole(client.getRole());

       myClient =  clientRepository.save(myClient);
        String token =  jwtService.createToken(myClient);
        return new AuthenticationResponse(token);

    }

    public AuthenticationResponse authenticate(UserDetails userDetails) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        userDetails.getPassword()
                )
        );
        Client client = clientRepository.findByUsername(userDetails.getUsername()).orElseThrow();
        String token = jwtService.createToken(client);
        return new AuthenticationResponse(token);
    }
}
