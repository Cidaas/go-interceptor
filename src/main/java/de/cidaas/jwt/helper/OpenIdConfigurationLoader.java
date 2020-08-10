package de.cidaas.jwt.helper;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HTTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

import de.cidaas.jwt.constants.CidaasConstants;
import de.cidaas.jwt.models.OpenIdConfiguration;

public class OpenIdConfigurationLoader {

	private final static Logger logger = LoggerFactory.getLogger(OpenIdConfigurationLoader.class);

	private static OpenIdConfigurationLoader instance;
	private OpenIdConfiguration openIdConfiguration;
	private ObjectMapper objectMapper;

	private OpenIdConfigurationLoader() {
		objectMapper = new ObjectMapper();
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper = objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

		openIdConfiguration = null;
	}

	public static synchronized OpenIdConfigurationLoader getInstance() {
		if (instance == null) {
			instance = new OpenIdConfigurationLoader();
		}
		return instance;
	}

	private void loadOpenIdConfiguration(String issuer) throws Exception {
		try {
			HttpGet request = new HttpGet(CidaasConstants.getOpenIdConfigURI(issuer));
			request.addHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

			HttpResponse response = HttpClientBuilder.create().build().execute(request);
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				openIdConfiguration = objectMapper.readValue(response.getEntity().getContent(), OpenIdConfiguration.class);
			} else {
				throw new Exception("The http rest call was not successful and returned: " + response.getStatusLine().getStatusCode());
			}
		} catch (Exception e) {
			throw new Exception("Error while resolving the openid-configuration" + e);
		}
	}

	public OpenIdConfiguration getOpenIdConfiguration(String issuer, boolean forceReload) throws Exception {

		if (forceReload) {
			openIdConfiguration = null;
		}

		if (openIdConfiguration == null) {
			loadOpenIdConfiguration(issuer);
		}

		return openIdConfiguration;
	}

	public String getIntrospectionURI(String issuer) {

		try {
			OpenIdConfiguration config = getOpenIdConfiguration(issuer, false);
			if (config != null && !Strings.isNullOrEmpty(config.getIntrospection_endpoint())) {
				return config.getIntrospection_endpoint();
			} else {
				throw new Exception("The introspection endpoint from the open id config object was null or emtpy");
			}
		} catch (Exception e) {
			logger.error("Couldn't get open id configuration from issuer, continuing with default url: " + 
					CidaasConstants.getIntrospectionDefaultURI(issuer), e);
		}

		return CidaasConstants.getIntrospectionDefaultURI(issuer);
	}
}
