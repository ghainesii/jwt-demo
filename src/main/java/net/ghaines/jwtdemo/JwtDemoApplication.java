package net.ghaines.jwtdemo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@SpringBootApplication
public class JwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}

}

@RestController
class AccessController {
	public static final String ALLOWED_METHODS = "allowed-methods";
	@Value("${jwt.secret}")
	String secret;

	@Bean
	String jwt() {
		String[] allowedMethods = { "/get", "/add" };
		return JWT.create()
				.withArrayClaim(ALLOWED_METHODS, allowedMethods)
				.withSubject("ghaines")
				.withExpiresAt(new Date(System.currentTimeMillis() + AuthenticationConfigConstants.EXPIRATION_TIME))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}
	@GetMapping("/check-access")
	ResponseEntity<?> checkAccess() {
		String token = jwt();
		System.out.println(token);
		List<String> body = new ArrayList<>();
		var claims = JWT.require(Algorithm.HMAC512(secret.getBytes()))
				.build()
				.verify(token.replace(AuthenticationConfigConstants.TOKEN_PREFIX, ""))
				.getClaims();
		claims.forEach((k, v) -> {
			System.out.println(k + "=" + v);
			if (k.equals(ALLOWED_METHODS)) {
				String[] methods = v.asArray(String.class);
				body.addAll(Arrays.stream(methods).toList());
			}
		});
		return ResponseEntity.ok(body);
	}
}
