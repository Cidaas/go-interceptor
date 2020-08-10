package de.cidaas.jwt;

public enum TokenType {
	 	ACCESS("access_token"),
	 	REFRESH("refresh_token");
	 
	    public final String typeHint;
	 
	    private TokenType(String typeHint) {
	        this.typeHint = typeHint;
	    }
}
