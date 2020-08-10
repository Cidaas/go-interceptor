package de.cidaas.jwt;

/**
 * The Enum TokenType.
 */
public enum TokenType {
	 	
	 	/** The access token. */
	 	ACCESS("access_token"),
	 	
	 	/** The refresh token. */
	 	REFRESH("refresh_token");
	 
	    /** The token type hint as string. */
    	public final String typeHint;
	 
	    /**
    	 * Instantiates a new token type.
    	 *
    	 * @param typeHint
    	 */
    	private TokenType(String typeHint) {
	        this.typeHint = typeHint;
	    }
}
