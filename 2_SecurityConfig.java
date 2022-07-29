package com.example.authpoc.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(
				(auth) -> auth.antMatchers("/register", "/home").permitAll().anyRequest().authenticated())
				.httpBasic(Customizer.withDefaults());
		return http.build();
	}

	@Bean
	public UserDetailsManager users(DataSource dataSource) {
		
		// Create a user using User class
		UserDetails user = User.withUsername("user").password("password").roles("USER")
				.build();
		
		// Create a jdbc details manager
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
		
		// call the createUser method of JdbcUserDetailsManager which implemented {@link org.springframework.security.provisioning.UserDetailsManager;}
		users.createUser(user);
		return users;
	}

	// we used here NoOpPasswordEncoder hence it will store all passwords like text 
	// It wont encrypt the password, it will store password directly
	// It is not recommended for production ready application
	@Bean
	PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

}
