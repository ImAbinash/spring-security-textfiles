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
// [Approach -1]: 
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
  
	
	
	
  // [Approach-2]: 
  // With default password encoder
  /*
  
  // This is using default password encoder which is bcrypt password encode
  
  @Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder().username("ImAbinash").password("test").authorities("Admin").build();
		return new InMemoryUserDetailsManager(userDetails);
	}
  
  */
  
	
	// [Approach-3]: 
	/*
	// Created Userdetails and then passed to InMemoryUserDetailsManager constructor then returned the object of InMemoryUserDetailsManager
	
	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
   		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
		UserDetails admin = User.withUsername("admin").password("12345").authorities("admin").build();
		UserDetails user = User.withUsername("user").password("12345").authorities("read").build();
		userDetailsService.createUser(admin);
		userDetailsService.createUser(user);
		return userDetailsService;
	}
	*/
	
}
