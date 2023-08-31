package com.sandbox.jwtTest;

import com.sandbox.jwtTest.entity.Role;
import com.sandbox.jwtTest.entity.UserEntity;
import com.sandbox.jwtTest.repository.RoleRepository;
import com.sandbox.jwtTest.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class JwtTestApplication {

	private final RoleRepository roleRepository;
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptEncoder;

	public JwtTestApplication(RoleRepository roleRepository, UserRepository userRepository, BCryptPasswordEncoder bCryptEncoder){
		this.roleRepository = roleRepository;
		this.userRepository = userRepository;
		this.bCryptEncoder = bCryptEncoder;
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtTestApplication.class, args);
	}

	@Bean
	public CommandLineRunner run() throws Exception{
		return (String[] args) -> {
			Role user = new Role("USER");
			roleRepository.save(user);
			Role admin = new Role("ADMIN");
			roleRepository.save(admin);

			List<UserEntity> users = new ArrayList<>();
			users.add(new UserEntity("Lucas", bCryptEncoder.encode("zerazeFZEUIU!!;"), "lucas.example@email.com", admin));
			users.add(new UserEntity("Aurélie", bCryptEncoder.encode("oihZTRdo(àdz"), "aurelie.example@email.com", user));
			users.add(new UserEntity("Yannick", bCryptEncoder.encode("oeerz45fs77zz$!'d;"), "yannick.example@email.com", user));
			userRepository.saveAll(users);
		};
	}
}
