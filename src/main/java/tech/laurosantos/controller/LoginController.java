package tech.laurosantos.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import tech.laurosantos.config.JwtUtils;
import tech.laurosantos.service.CustomUserDetailsService;

@RestController
@RequestMapping("/api/auth")
public class LoginController {
	private final AuthenticationManager authenticationManager;
	private final CustomUserDetailsService customUserDetailsService;
	private final JwtUtils jwtUtils;

	public LoginController(AuthenticationManager authenticationManager,
			CustomUserDetailsService customUserDetailsService, JwtUtils jwtUtils) {
		this.authenticationManager = authenticationManager;
		this.customUserDetailsService = customUserDetailsService;
		this.jwtUtils = jwtUtils;
	}

	@PostMapping("/login")
	public String login(@RequestParam String username, @RequestParam String password) throws AuthenticationException {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		var userDetails = customUserDetailsService.loadUserByUsername(username);
		return jwtUtils.generateToken(userDetails.getUsername());
	}
}
