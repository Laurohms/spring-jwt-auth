package tech.laurosantos.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import tech.laurosantos.service.UserService;

@RestController
@RequestMapping("/api/auth")
public class RegisterController {
	private final UserService userService;

	public RegisterController(UserService userService) {
		this.userService = userService;
	}

	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestParam String username, @RequestParam String password) {
		userService.registerUser(username, password);
		return ResponseEntity.ok("User registered successfully");
	}

}
