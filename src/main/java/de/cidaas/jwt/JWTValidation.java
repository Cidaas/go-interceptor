package de.cidaas.jwt;

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

	public JWTValidation() {
		objectMapper = new ObjectMapper();
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
	}
	
	public IntrospectionResponse validateWithIntrospection(String token, String tokenTypeHint, String clientId, String introspectionURI) throws JWTVerificationException {
		return validateWithIntrospection(new IntrospectionRequest(token, tokenTypeHint, clientId), introspectionURI);
	}
	
	public IntrospectionResponse validateWithIntrospection(IntrospectionRequest tokenInfo, String introspectionURI) throws JWTVerificationException {
		
		try {
			HttpPost request = new HttpPost(introspectionURI);
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
