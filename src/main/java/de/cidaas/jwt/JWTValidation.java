package de.cidaas.jwt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTValidation {
	private ObjectMapper objectMapper;

	private static JWTValidation jwtValidation;

	public static synchronized JWTValidation getInstance() {
		if (jwtValidation == null) {
			jwtValidation = new JWTValidation();
		}
		return jwtValidation;
	}

	public JWTValidation() {
		objectMapper = new ObjectMapper();
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
	}
}
