package de.cidaas.jwt;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.cidaas.jwt.exceptions.JWTVerificationException;
import de.cidaas.jwt.models.IntrospectionRequest;
import de.cidaas.jwt.models.IntrospectionResponse;

/**
 * The Class JWTValidation.
 */
public class JWTValidation {
	
	/** The object mapper. */
	private ObjectMapper objectMapper;
	
	/** Proxy configuration. */
	private HttpHost proxy;
	
	/** If the default system properties should be used for the HTTPClientBuilder **/
	private boolean useSystemProperties = false;

	/**
	 * Instantiates a new JWT validation.
	 */
	public JWTValidation() {
		objectMapper = new ObjectMapper();
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
	}
	
	/**
	 * Sets the proxy.
	 *
	 * @param proxy the new proxy
	 */
	public void setProxy(final HttpHost proxy){
		this.proxy = proxy;
	}
	
	/**
	 * Sets the useSystemProperties.
	 * 
	 * @param useSystemProperties
	 */
	public void setUseSystemProperties(boolean useSystemProperties) {
		this.useSystemProperties = useSystemProperties;
	}
	
	/**
	 * Validate with introspection.
	 *
	 * @param token the token as string
	 * @param tokenTypeHint the token type hint
	 * @param clientId the client id
	 * @param introspectionURL the URL of the introspection end point
	 * @return the introspection response
	 * @throws JWTVerificationException the JWT verification exception
	 */
	public IntrospectionResponse validateWithIntrospection(String token, String tokenTypeHint, String clientId, String introspectionURL) throws JWTVerificationException {
		return validateWithIntrospection(new IntrospectionRequest(token, tokenTypeHint, clientId), introspectionURL);
	}
	
	/**
	 * Validate with introspection.
	 *
	 * @param introspectionRequest the request object for the introspection call
	 * @param introspectionURL the URL of the introspection end point
	 * @return the introspection response
	 * @throws JWTVerificationException the JWT verification exception
	 */
	public IntrospectionResponse validateWithIntrospection(IntrospectionRequest introspectionRequest, String introspectionURL) throws JWTVerificationException {
		
		try {
			HttpPost request = new HttpPost(introspectionURL);
			request.setEntity(new StringEntity(objectMapper.writeValueAsString(introspectionRequest)));
			request.addHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());
			
			HttpClientBuilder builder;
			if (useSystemProperties) {
				builder = HttpClients.custom().useSystemProperties();
			} else {				
				builder = HttpClientBuilder.create();
			}
			
			if(proxy != null)
				builder.setProxy(proxy);
			
			HttpResponse response = builder.build().execute(request);
			
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
