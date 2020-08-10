package de.cidaas.jwt.models;

import java.io.Serializable;

/**
 * The Class IntrospectionRequest.
 */
public class IntrospectionRequest implements Serializable {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 7429976226853857864L;
	
	/** The token. */
	private String token;
    
    /** The token type hint. */
    private String token_type_hint;
    
    /** The client id. */
    private String client_id;

    /**
     * Instantiates a new introspection request.
     *
     * @param token the token
     * @param tokenType the token type
     * @param clientId the client id
     */
    public IntrospectionRequest(String token, String tokenType, String clientId) {
    	this.token = token;
    	this.token_type_hint = tokenType;
    	this.client_id = clientId;
    }
    
    /**
     * Instantiates a new introspection request.
     *
     * @param token the token
     * @param tokenType the token type
     */
    public IntrospectionRequest(String token, String tokenType) {
    	this(token, tokenType, null);
    }
    
    /**
     * Gets the token.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets the token.
     *
     * @param token the new token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Gets the token type hint.
     *
     * @return the token type hint
     */
    public String getToken_type_hint() {
        return token_type_hint;
    }

    /**
     * Sets the token type hint.
     *
     * @param token_type_hint the new token type hint
     */
    public void setToken_type_hint(String token_type_hint) {
        this.token_type_hint = token_type_hint;
    }

    /**
     * Gets the client id.
     *
     * @return the client id
     */
    public String getClient_id() {
        return client_id;
    }

    /**
     * Sets the client id.
     *
     * @param client_id the new client id
     */
    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }
}
