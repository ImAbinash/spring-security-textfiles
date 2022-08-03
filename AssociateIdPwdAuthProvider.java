package com.bipros.hrms.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.bipros.hrms.entity.Associate;
import com.bipros.hrms.property.ApiResponseProperty;
import com.bipros.hrms.repository.AssociateRepo;

@Component
public class AssociateIdPwdAuthProvider implements AuthenticationProvider {

	@Autowired
	private ApiResponseProperty property;
	
	@Autowired
	private AssociateRepo associateRepo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String associateId = authentication.getName();
		String password = authentication.getCredentials().toString();
		Associate associate = associateRepo.findByAssociateNumber(associateId);
		if(associate != null) {
			if(passwordEncoder.matches(password, associate.getPassword())) {
				return new UsernamePasswordAuthenticationToken(associateId, password);
			}else {
				throw new BadCredentialsException(property.getInvalidCredential());
			}
		}
		
		throw new BadCredentialsException(property.getInvalidCredential());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
