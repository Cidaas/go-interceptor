package de.cidaas.jwt.constants;

public class CidaasConstants {

	public static final String OPENID_CONFIG_PATH = "/.well-known/openid-configuration";
	public static final String INTROSPECTION_DEFAULT_PATH = "/token-srv/introspect";
	
	public static String getOpenIdConfigURI(String issuer) {
		return issuer + OPENID_CONFIG_PATH;
	}
	
	public static String getIntrospectionDefaultURI(String issuer) {
		return issuer + CidaasConstants.INTROSPECTION_DEFAULT_PATH;
	}
}
