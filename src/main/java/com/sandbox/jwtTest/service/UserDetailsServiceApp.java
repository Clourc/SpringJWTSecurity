package com.sandbox.jwtTest.service;

import com.sandbox.jwtTest.jwt.UserPrincipal;
import com.sandbox.jwtTest.repository.UserRepository;
import org.springframework.stereotype.Component;

@Component
public class UserDetailsServiceApp {

    private final UserRepository userRepository;

    public UserDetailsServiceApp(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserPrincipal loadUserByEmail(String email) {
        if (userRepository.findByEmail(email).isPresent()) {
            return new UserPrincipal(userRepository.findByEmail(email).get());
        }
        throw new RuntimeException("Aucun utilisateur trouvé par cet email");
    }
}
