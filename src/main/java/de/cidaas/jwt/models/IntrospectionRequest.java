package de.cidaas.jwt.models;

import java.io.Serializable;

public class IntrospectionRequest implements Serializable {

	private static final long serialVersionUID = 7429976226853857864L;
	
	private String token;
    private String token_type_hint;
    private String client_id;

    public IntrospectionRequest(String token, String tokenType, String clientId) {
    	this.token = token;
    	this.token_type_hint = tokenType;
    	this.client_id = clientId;
    }
    
    public IntrospectionRequest(String token, String tokenType) {
    	this(token, tokenType, null);
    }
    
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getToken_type_hint() {
        return token_type_hint;
    }

    public void setToken_type_hint(String token_type_hint) {
        this.token_type_hint = token_type_hint;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }
}
