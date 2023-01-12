package com.sid.securityservice.web;


import com.sid.securityservice.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {
    private JwtEncoder jwtEncoder;
    private AuthenticationManager authenticationManager;
    private JwtDecoder jwtDecoder;
    private UserDetailsService userDetailsService;

    public AuthService authService;

    public AuthController(JwtEncoder jwtEncoder, AuthenticationManager authenticationManager, JwtDecoder jwtDecoder, UserDetailsService userDetailsService, AuthService authService) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
        this.authService = authService;
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> jwtToken(String grantType, String username, String password, boolean withRefreshToken, String refreshToken){
        if(username == null){
            return new ResponseEntity<>(Map.of("errorMessage", "Username is Required!"), HttpStatus.UNAUTHORIZED);
        }
        if(password == null){
            return new ResponseEntity<>(Map.of("errorMessage", "Password is Required!"), HttpStatus.UNAUTHORIZED);
        }
        if ((grantType.equals("refreshToken") && refreshToken == null)) {
            return new ResponseEntity<>(Map.of("errorMessage", "Refresh Token is required!"), HttpStatus.UNAUTHORIZED);
        }
        Map<String, String> idToken = new HashMap<>();
        authService.authenticate(grantType,username,password,withRefreshToken,refreshToken,idToken);

        return new ResponseEntity<>(idToken, HttpStatus.OK);
    }
}//Il reste d'autre cas exceptionnel à traiter comme si l'utilisateur n'existe pas.......
