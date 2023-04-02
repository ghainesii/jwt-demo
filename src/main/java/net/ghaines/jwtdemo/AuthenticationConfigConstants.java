package net.ghaines.jwtdemo;

public class AuthenticationConfigConstants {
	public static final long EXPIRATION_TIME = 90_000; // 15 min
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
}
