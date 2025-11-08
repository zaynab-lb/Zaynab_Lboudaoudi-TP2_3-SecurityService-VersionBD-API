package com.example.securityservice.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class API
{
    private final JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private UserDetailsService userDetailsService;

    public API(AuthenticationManager authenticationManager, JwtDecoder jwtDecoder , JwtEncoder jwtEncoder, UserDetailsService userDetailsService)
    {
        this.authenticationManager = authenticationManager;
        this.jwtDecoder = jwtDecoder;
        this.jwtEncoder = jwtEncoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    Map<String , String> login(String username, String password) {
        Map<String, String> ID_token = new HashMap<>();
        Instant instant = Instant.now();

        //vérifier l'authentification
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        //get scope
        String scope = authenticate.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));
        //Création Id token
        //1. Access Token

        JwtClaimsSet jwtClaimsSet_accessToken = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .build();

        String Access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();

        // 2. Refresh token
        JwtClaimsSet jwtClaimsSet_refreshToken = JwtClaimsSet.builder()
                .subject(authenticate.getName()) // Toujours Add Le nome d'utilisateur
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))
                .build();

        String Refresh_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refreshToken)).getTokenValue();

        ID_token.put("Access_Token", Access_token);
        ID_token.put("Refresh_Token", Refresh_token);

        return ID_token;

    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(String refresh_token) {

        Map<String, String> ID_token = new HashMap<>();
        Instant instant = Instant.now();

        if(refresh_token == null){
            ID_token.put("access_token", "null" + HttpStatus.UNAUTHORIZED);
            return ID_token;
        }
        //verify signature
        Jwt decodedToken = jwtDecoder.decode(refresh_token);

        String username = decodedToken.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        //create Access Token

        //get scope
        String scope = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

        // Access Token
        JwtClaimsSet jwtClaimsSet_accessToken = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuer("Security_Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .build();
        String access_token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_accessToken)).getTokenValue();

        ID_token.put("access_token", access_token);
        ID_token.put("refresh_token", refresh_token);

        return ID_token;
    }
}
