package de.cidaas.jwt.helper;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

import de.cidaas.jwt.constants.CidaasConstants;
import de.cidaas.jwt.models.OpenIdConfiguration;

/**
 * The Class OpenIdConfigurationLoader.
 */
public class OpenIdConfigurationLoader {

	/** The Constant logger. */
	private final static Logger logger = LoggerFactory.getLogger(OpenIdConfigurationLoader.class);

	/** The instance. */
	private static OpenIdConfigurationLoader instance;
	
	/** The open id configuration. */
	private OpenIdConfiguration openIdConfiguration;
	
	/** The object mapper. */
	private ObjectMapper objectMapper;
	
	/** Proxy configuration. */
	private HttpHost proxy;
	
	/** If the default system properties should be used for the HTTPClientBuilder **/
	private boolean useSystemProperties = false;

	/**
	 * Instantiates a new open id configuration loader.
	 */
	private OpenIdConfigurationLoader() {
		objectMapper = new ObjectMapper();
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

		openIdConfiguration = null;
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
	 * Gets the single instance of OpenIdConfigurationLoader.
	 *
	 * @return single instance of OpenIdConfigurationLoader
	 */
	public static synchronized OpenIdConfigurationLoader getInstance() {
		if (instance == null) {
			instance = new OpenIdConfigurationLoader();
		}
		return instance;
	}

	/**
	 * Load open id configuration.
	 *
	 * @param issuer the base URL of the issuer
	 * @throws Exception the exception
	 */
	private void loadOpenIdConfiguration(String issuer) throws Exception {
		try {
			HttpGet request = new HttpGet(CidaasConstants.getOpenIdConfigURL(issuer));
			request.addHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());
			
			HttpClientBuilder builder = null;
			
			if (useSystemProperties) {
				builder = HttpClients.custom().useSystemProperties();
			} else {				
				builder = HttpClientBuilder.create();
			}
			
			if(proxy != null)
				builder.setProxy(proxy);
			
			HttpResponse response = builder.build().execute(request);
			
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				openIdConfiguration = objectMapper.readValue(response.getEntity().getContent(), OpenIdConfiguration.class);
			} else {
				throw new Exception("The http rest call was not successful and returned: " + response.getStatusLine().getStatusCode());
			}
		} catch (Exception e) {
			throw new Exception("Error while resolving the openid-configuration", e);
		}
	}

	/**
	 * Gets the open id configuration.
	 *
	 * @param issuer the base URL of the issuer
	 * @param forceReload if the open id configuration should be fetched again
	 * @return the open id configuration
	 * @throws Exception the exception
	 */
	public OpenIdConfiguration getOpenIdConfiguration(String issuer, boolean forceReload) throws Exception {

		if (openIdConfiguration == null || forceReload) {
			loadOpenIdConfiguration(issuer);
		}

		return openIdConfiguration;
	}

	/**
	 * Gets the introspection URI from the open id configuration object.
	 * If the configuration could not be loaded, this method returns the default URI
	 * for the introspection end point
	 *
	 * @param issuer the base URL of the issuer
	 * @return the introspection URL from the issuer
	 */
	public String getIntrospectionURL(String issuer) {

		try {
			OpenIdConfiguration config = getOpenIdConfiguration(issuer, false);
			if (config != null && !Strings.isNullOrEmpty(config.getIntrospection_endpoint())) {
				return config.getIntrospection_endpoint();
			} else {
				throw new Exception("The introspection endpoint from the open id config object was null or emtpy");
			}
		} catch (Exception e) {
			logger.error("Couldn't get open id configuration from issuer, continuing with default url: " + 
					CidaasConstants.getIntrospectionDefaultURL(issuer), e);
		}

		return CidaasConstants.getIntrospectionDefaultURL(issuer);
	}
}
