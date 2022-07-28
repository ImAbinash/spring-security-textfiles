package com.example.authpoc.config;

import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	
	
	// Permited register and home url other urls must authenticated.
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((auth) -> auth.antMatchers("/register","/home").permitAll().anyRequest()
				.authenticated()).httpBasic(Customizer.withDefaults());
		return http.build();
	}
/*
// This doesn't contain default password encode hence we created nopassword encoder 
// For default password encode see the bellow commented section 


	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails userDetails = User.withUsername("ImAbinash").password("test").authorities("Admin").build();
		return new InMemoryUserDetailsManager(userDetails);
	}
	
	@Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
	*/
  //  --------------------------------- OR ---------------------------------
  // With default password encoder
  /*
  
  // This is using default password encoder which is bcrypt password encode
  
  @Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder().username("ImAbinash").password("test").authorities("Admin").build();
		return new InMemoryUserDetailsManager(userDetails);
	}
  
  */
  
  
  
  
	
}
