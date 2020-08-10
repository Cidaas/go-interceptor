package de.cidaas.jwt.models;

/**
 * The Class IntrospectionResponse.
 */
public class IntrospectionResponse {
	
	/** The active. */
	private boolean active = false;
	
	/** The token type. */
	private String token_type;
	
	/** The audience. */
	private String aud;
	
	/** The expire date. */
	private long exp;
	
	/** The iat. */
	private long iat;
	
	/** The issuer. */
	private String iss;
	
	/** The jti. */
	private String jti;
	
	/** The sub. */
	private String sub;
	
	/** The roles. */
	private String[] roles;
	
	/** The scopes. */
	private String[] scopes;
	
	/** The scope. */
	private String scope;

	/**
	 * Checks if is active.
	 *
	 * @return true, if is active
	 */
	public boolean isActive() {
		return active;
	}

	/**
	 * Sets the active.
	 *
	 * @param active the new active
	 */
	public void setActive(boolean active) {
		this.active = active;
	}

	/**
	 * Gets the scope.
	 *
	 * @return the scope
	 */
	public String getScope() {
		return scope;
	}

	/**
	 * Sets the scope.
	 *
	 * @param scope the new scope
	 */
	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * Gets the token type.
	 *
	 * @return the token type
	 */
	public String getToken_type() {
		return token_type;
	}

	/**
	 * Sets the token type.
	 *
	 * @param token_type the new token type
	 */
	public void setToken_type(String token_type) {
		this.token_type = token_type;
	}

	/**
	 * Gets the expire date.
	 *
	 * @return the expire date
	 */
	public long getExp() {
		return exp;
	}

	/**
	 * Sets the expire date.
	 *
	 * @param exp the new expire date
	 */
	public void setExp(long exp) {
		this.exp = exp;
	}

	/**
	 * Gets the iat.
	 *
	 * @return the iat
	 */
	public long getIat() {
		return iat;
	}

	/**
	 * Sets the iat.
	 *
	 * @param iat the new iat
	 */
	public void setIat(long iat) {
		this.iat = iat;
	}

	/**
	 * Gets the subject.
	 *
	 * @return the subject
	 */
	public String getSub() {
		return sub;
	}

	/**
	 * Sets the subject.
	 *
	 * @param sub the new subject
	 */
	public void setSub(String sub) {
		this.sub = sub;
	}

	/**
	 * Gets the audience.
	 *
	 * @return the audience
	 */
	public String getAud() {
		return aud;
	}

	/**
	 * Sets the audience.
	 *
	 * @param aud the new audience
	 */
	public void setAud(String aud) {
		this.aud = aud;
	}

	/**
	 * Gets the issuer.
	 *
	 * @return the issuer
	 */
	public String getIss() {
		return iss;
	}

	/**
	 * Sets the issuer.
	 *
	 * @param iss the new issuer
	 */
	public void setIss(String iss) {
		this.iss = iss;
	}

	/**
	 * Gets the jti.
	 *
	 * @return the jti
	 */
	public String getJti() {
		return jti;
	}

	/**
	 * Sets the jti.
	 *
	 * @param jti the new jti
	 */
	public void setJti(String jti) {
		this.jti = jti;
	}

	/**
	 * Gets the scopes.
	 *
	 * @return the scopes
	 */
	public String[] getScopes() {
		return scopes;
	}

	/**
	 * Sets the scopes.
	 *
	 * @param scopes the new scopes
	 */
	public void setScopes(String[] scopes) {
		this.scopes = scopes;
	}

	/**
	 * Gets the roles.
	 *
	 * @return the roles
	 */
	public String[] getRoles() {
		return roles;
	}

	/**
	 * Sets the roles.
	 *
	 * @param roles the new roles
	 */
	public void setRoles(String[] roles) {
		this.roles = roles;
	}
}
