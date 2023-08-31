package com.sandbox.jwtTest.service;

import com.sandbox.jwtTest.dto.UserDto;
import com.sandbox.jwtTest.entity.User;
import com.sandbox.jwtTest.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bcryptEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bcryptEncoder) {
        this.userRepository = userRepository;
        this.bcryptEncoder = bcryptEncoder;
    }

    //Test password regex
    public boolean checkHashedPassword(String password) {
        //A implémenter
        if (password != null) {
            Pattern pattern = Pattern.compile("(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?=\\S+$).{8,}");
            return pattern.matcher(password).matches();
        } else {
            throw new RuntimeException("Aucun mot de passe trouvé");
        }
    }

    public boolean checkEmail(String email) {
        return userRepository.findByEmail(email).isEmpty();
    }

    public UserDto register(UserDto userDto) {
        if (!checkHashedPassword(userDto.getPassword())) {
            throw new RuntimeException("Le mot de passe n'est pas assez fort");
        }
        if (!checkEmail(userDto.getEmail())) {
            throw new RuntimeException("L'email existe déjà");
        }

        String hashedpassword = bcryptEncoder.encode(userDto.getPassword());

        User newUser = new User(userDto.getUsername(), hashedpassword, userDto.getEmail());
        userRepository.save(newUser);
        return userDto;
    }

    public boolean verifyHashedPasswordDuringLogin(String password, String hashedPassword){
        return bcryptEncoder.matches(password, hashedPassword);
    }

    public UserDto login(UserDto userDto){
        User user = getUserByEmail(userDto.getEmail());
        if(!verifyHashedPasswordDuringLogin(userDto.getPassword(), user.getPassword())) {
            throw new RuntimeException("Mot de pass incorrect");
        }
        return userDto;
    }

    public User getUserByEmail(String email) {
        if (userRepository.findByEmail(email).isPresent()) {
            return userRepository.findByEmail(email).get();
        } else {
            throw new RuntimeException("L'email n'existe pas");
        }
    }
}
