package de.cidaas.jwt.constants;

/**
 * The Class CidaasConstants.
 */
public class CidaasConstants {

	/** The Constant OPENID_CONFIG_PATH. */
	public static final String OPENID_CONFIG_PATH = "/.well-known/openid-configuration";
	
	/** The Constant INTROSPECTION_DEFAULT_PATH. */
	public static final String INTROSPECTION_DEFAULT_PATH = "/token-srv/introspect";
	
	/**
	 * Gets the open id config URL.
	 *
	 * @param issuer the base URL of the issuer
	 * @return the open id config URL
	 */
	public static String getOpenIdConfigURL(String issuer) {
		return issuer + OPENID_CONFIG_PATH;
	}
	
	/**
	 * Gets the introspection default URL.
	 *
	 * @param issuer the base URL of the issuer
	 * @return the introspection default URL
	 */
	public static String getIntrospectionDefaultURL(String issuer) {
		return issuer + CidaasConstants.INTROSPECTION_DEFAULT_PATH;
	}
}
