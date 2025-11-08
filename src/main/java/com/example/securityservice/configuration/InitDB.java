package com.example.securityservice.configuration;

import com.example.securityservice.entities.Role;
import com.example.securityservice.entities.User;
import com.example.securityservice.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class InitDB {
    @Bean
    CommandLineRunner initUsers(UserRepository userRepository, PasswordEncoder encoder) {
        return args -> {
            if (userRepository.count() == 0) {
                userRepository.save(new User(null, "user1", encoder.encode("1234"), Role.USER));
                userRepository.save(new User(null, "admin", encoder.encode("admin123"), Role.ADMIN));
                System.out.println("✅ Utilisateurs ajoutés dans la base !");
            }
        };
    }
}

