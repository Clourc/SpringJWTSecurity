package com.sandbox.jwtTest.service;

import com.sandbox.jwtTest.jwt.UserPrincipal;
import com.sandbox.jwtTest.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserDetailsServiceApp {

    private final UserRepository userRepository;

    public UserDetailsServiceApp(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (userRepository.findByUsername(username).isPresent()) {
            return new UserPrincipal(userRepository.findByUsername(username).get());
        }
        throw new RuntimeException("Aucun utilisateur trouvé par ce username");
    }
}
