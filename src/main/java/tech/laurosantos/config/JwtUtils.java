package tech.laurosantos.config;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

	private final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generates a secure key for HS256

	public String generateToken(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // Token valid for 10 hours
				.signWith(key) // Use the secure key here
				.compact();
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// Extract expiration time from the token
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	// Extract specific claims
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	// Extract all claims
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(key) // Use the secure key for parsing the token
				.build().parseClaimsJws(token).getBody();
	}

	// Check if the token has expired
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	// Validate the token (check if it's valid and matches the user)
	public boolean validateToken(String token, String username) {
		final String tokenUsername = extractUsername(token);
		return tokenUsername.equals(username) && !isTokenExpired(token);
	}
}