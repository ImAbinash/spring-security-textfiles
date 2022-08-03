package com.bipros.hrms.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bipros.hrms.security.provider.AssociateIdPwdAuthProvider;

@Configuration
public class AppSecurityConfig {

	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		
		// Create custom AuthenticationManager
		AuthenticationManagerBuilder authBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authBuilder.authenticationProvider(assoicateIdPwdAuthProvider());
		AuthenticationManager authManager = authBuilder.build();
		
		http.authorizeHttpRequests(
				(auth) -> auth.antMatchers("/authenticate", "/register").permitAll().anyRequest().authenticated())
		.authenticationManager(authManager);
		http.httpBasic();
		return http.build();
	}
	
	
	@Bean
	public AssociateIdPwdAuthProvider assoicateIdPwdAuthProvider() {
		AssociateIdPwdAuthProvider authProvider = new AssociateIdPwdAuthProvider();
		return authProvider;
	}
	

	@Bean
	PasswordEncoder getPasswordEncoder() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
}
