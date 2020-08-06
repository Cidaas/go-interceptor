package de.cidaas.jwt;

import java.net.URI;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HTTP;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.cidaas.jwt.exceptions.JWTVerificationException;
import de.cidaas.jwt.models.IntrospectionRequest;
import de.cidaas.jwt.models.IntrospectionResponse;

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
	
	public IntrospectionResponse validateWithIntrospection(String token, String tokenType, String clientId, String clientSecret, String issuer) throws JWTVerificationException {
		IntrospectionRequest requestInfo = new IntrospectionRequest(token, tokenType);
		requestInfo.setClient_id(clientId);
		requestInfo.setClient_secret(clientSecret);
		
		return validateWithIntrospection(requestInfo, issuer);
	}
	
	public IntrospectionResponse validateWithIntrospection(IntrospectionRequest tokenInfo, String issuer) throws JWTVerificationException {
		try {
			HttpPost request = new HttpPost(new URI(issuer + "/token-srv/introspect"));
			request.setEntity(new StringEntity(objectMapper.writeValueAsString(tokenInfo)));
			request.addHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

			HttpResponse response = HttpClientBuilder.create().build().execute(request);
			
			IntrospectionResponse introspectionResponse = new IntrospectionResponse();
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				introspectionResponse = objectMapper.readValue(response.getEntity().getContent(), IntrospectionResponse.class);
			} 
			return introspectionResponse;
		} catch (Exception e) {
			throw new JWTVerificationException("Error during request to the introspection endpoint", e);
		}
	}
}
