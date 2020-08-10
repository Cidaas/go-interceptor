package de.cidaas.jwt.models;

/**
 * The Class OpenIdConfiguration.
 */
public class OpenIdConfiguration {

	/** The issuer. */
	private String issuer;
	
	/** The authorization endpoint. */
	private String authorization_endpoint;
	
	/** The token endpoint. */
	private String token_endpoint;
	
	/** The userinfo endpoint. */
	private String userinfo_endpoint;
	
	/** The jwks uri. */
	private String jwks_uri;
	
	/** The scopes supported. */
	private String[] scopes_supported;
	
	/** The response types supported. */
	private String[] response_types_supported;
	
	/** The response modes supported. */
	private String[] response_modes_supported;
	
	/** The subject types supported. */
	private String[] subject_types_supported;
	
	/** The id token signing alg values supported. */
	private String[] id_token_signing_alg_values_supported;
	
	/** The token endpoint auth methods supported. */
	private String[] token_endpoint_auth_methods_supported;
	
	/** The claims supported. */
	private String[] claims_supported;
	
	/** The token endpoint auth signing alg values supported. */
	private String[] token_endpoint_auth_signing_alg_values_supported;
	
	/** The check session iframe. */
	private String check_session_iframe;
	
	/** The end session endpoint. */
	private String end_session_endpoint;
	
	/** The registration endpoint. */
	private String registration_endpoint;
	
	/** The acr values supported. */
	private String[] acr_values_supported;
	
	/** The userinfo signing alg values supported. */
	private String[] userinfo_signing_alg_values_supported;
	
	/** The userinfo encryption alg values supported. */
	private String[] userinfo_encryption_alg_values_supported;
	
	/** The userinfo encryption enc values supported. */
	private String[] userinfo_encryption_enc_values_supported;
	
	/** The id token encryption alg values supported. */
	private String[] id_token_encryption_alg_values_supported;
	
	/** The id token encryption enc values supported. */
	private String[] id_token_encryption_enc_values_supported;
	
	/** The request object signing alg values supported. */
	private String[] request_object_signing_alg_values_supported;
	
	/** The request object encryption alg values supported. */
	private String[] request_object_encryption_alg_values_supported;
	
	/** The request object encryption enc values supported. */
	private String[] request_object_encryption_enc_values_supported;
	
	/** The display values supported. */
	private String[] display_values_supported;
	
	/** The claim types supported. */
	private String[] claim_types_supported;
	
	/** The claims parameter supported. */
	private Boolean claims_parameter_supported;
	
	/** The service documentation. */
	private String service_documentation;
	
	/** The ui locales supported. */
	private String[] ui_locales_supported;
	
	/** The introspection endpoint. */
	private String introspection_endpoint;
	
	/** The introspection async update endpoint. */
	private String introspection_async_update_endpoint;
	
	/** The revocation endpoint. */
	private String revocation_endpoint;
	
	/** The claims locales supported. */
	private String[] claims_locales_supported;
	
	/** The request parameter supported. */
	private Boolean request_parameter_supported;
	
	/** The request uri parameter supported. */
	private Boolean request_uri_parameter_supported;
	
	/** The require request uri registration. */
	private Boolean require_request_uri_registration;
	
	/** The op policy uri. */
	private String op_policy_uri;
	
	/** The op tos uri. */
	private String op_tos_uri;
	
	/** The grant types supported. */
	private String[] grant_types_supported;
	
	/** The code challenge methods supported. */
	private String[] code_challenge_methods_supported;

	/**
	 * Gets the issuer.
	 *
	 * @return the issuer
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * Sets the issuer.
	 *
	 * @param issuer the new issuer
	 */
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	/**
	 * Gets the authorization endpoint.
	 *
	 * @return the authorization endpoint
	 */
	public String getAuthorization_endpoint() {
		return authorization_endpoint;
	}

	/**
	 * Sets the authorization endpoint.
	 *
	 * @param authorization_endpoint the new authorization endpoint
	 */
	public void setAuthorization_endpoint(String authorization_endpoint) {
		this.authorization_endpoint = authorization_endpoint;
	}

	/**
	 * Gets the token endpoint.
	 *
	 * @return the token endpoint
	 */
	public String getToken_endpoint() {
		return token_endpoint;
	}

	/**
	 * Sets the token endpoint.
	 *
	 * @param token_endpoint the new token endpoint
	 */
	public void setToken_endpoint(String token_endpoint) {
		this.token_endpoint = token_endpoint;
	}

	/**
	 * Gets the userinfo endpoint.
	 *
	 * @return the userinfo endpoint
	 */
	public String getUserinfo_endpoint() {
		return userinfo_endpoint;
	}

	/**
	 * Sets the userinfo endpoint.
	 *
	 * @param userinfo_endpoint the new userinfo endpoint
	 */
	public void setUserinfo_endpoint(String userinfo_endpoint) {
		this.userinfo_endpoint = userinfo_endpoint;
	}

	/**
	 * Gets the jwks uri.
	 *
	 * @return the jwks uri
	 */
	public String getJwks_uri() {
		return jwks_uri;
	}

	/**
	 * Sets the jwks uri.
	 *
	 * @param jwks_uri the new jwks uri
	 */
	public void setJwks_uri(String jwks_uri) {
		this.jwks_uri = jwks_uri;
	}

	/**
	 * Gets the scopes supported.
	 *
	 * @return the scopes supported
	 */
	public String[] getScopes_supported() {
		return scopes_supported;
	}

	/**
	 * Sets the scopes supported.
	 *
	 * @param scopes_supported the new scopes supported
	 */
	public void setScopes_supported(String[] scopes_supported) {
		this.scopes_supported = scopes_supported;
	}

	/**
	 * Gets the response types supported.
	 *
	 * @return the response types supported
	 */
	public String[] getResponse_types_supported() {
		return response_types_supported;
	}

	/**
	 * Sets the response types supported.
	 *
	 * @param response_types_supported the new response types supported
	 */
	public void setResponse_types_supported(String[] response_types_supported) {
		this.response_types_supported = response_types_supported;
	}

	/**
	 * Gets the response modes supported.
	 *
	 * @return the response modes supported
	 */
	public String[] getResponse_modes_supported() {
		return response_modes_supported;
	}

	/**
	 * Sets the response modes supported.
	 *
	 * @param response_modes_supported the new response modes supported
	 */
	public void setResponse_modes_supported(String[] response_modes_supported) {
		this.response_modes_supported = response_modes_supported;
	}

	/**
	 * Gets the subject types supported.
	 *
	 * @return the subject types supported
	 */
	public String[] getSubject_types_supported() {
		return subject_types_supported;
	}

	/**
	 * Sets the subject types supported.
	 *
	 * @param subject_types_supported the new subject types supported
	 */
	public void setSubject_types_supported(String[] subject_types_supported) {
		this.subject_types_supported = subject_types_supported;
	}

	/**
	 * Gets the id token signing alg values supported.
	 *
	 * @return the id token signing alg values supported
	 */
	public String[] getId_token_signing_alg_values_supported() {
		return id_token_signing_alg_values_supported;
	}

	/**
	 * Sets the id token signing alg values supported.
	 *
	 * @param id_token_signing_alg_values_supported the new id token signing alg values supported
	 */
	public void setId_token_signing_alg_values_supported(String[] id_token_signing_alg_values_supported) {
		this.id_token_signing_alg_values_supported = id_token_signing_alg_values_supported;
	}

	/**
	 * Gets the token endpoint auth methods supported.
	 *
	 * @return the token endpoint auth methods supported
	 */
	public String[] getToken_endpoint_auth_methods_supported() {
		return token_endpoint_auth_methods_supported;
	}

	/**
	 * Sets the token endpoint auth methods supported.
	 *
	 * @param token_endpoint_auth_methods_supported the new token endpoint auth methods supported
	 */
	public void setToken_endpoint_auth_methods_supported(String[] token_endpoint_auth_methods_supported) {
		this.token_endpoint_auth_methods_supported = token_endpoint_auth_methods_supported;
	}

	/**
	 * Gets the claims supported.
	 *
	 * @return the claims supported
	 */
	public String[] getClaims_supported() {
		return claims_supported;
	}

	/**
	 * Sets the claims supported.
	 *
	 * @param claims_supported the new claims supported
	 */
	public void setClaims_supported(String[] claims_supported) {
		this.claims_supported = claims_supported;
	}

	/**
	 * Gets the token endpoint auth signing alg values supported.
	 *
	 * @return the token endpoint auth signing alg values supported
	 */
	public String[] getToken_endpoint_auth_signing_alg_values_supported() {
		return token_endpoint_auth_signing_alg_values_supported;
	}

	/**
	 * Sets the token endpoint auth signing alg values supported.
	 *
	 * @param token_endpoint_auth_signing_alg_values_supported the new token endpoint auth signing alg values supported
	 */
	public void setToken_endpoint_auth_signing_alg_values_supported(
			String[] token_endpoint_auth_signing_alg_values_supported) {
		this.token_endpoint_auth_signing_alg_values_supported = token_endpoint_auth_signing_alg_values_supported;
	}

	/**
	 * Gets the check session iframe.
	 *
	 * @return the check session iframe
	 */
	public String getCheck_session_iframe() {
		return check_session_iframe;
	}

	/**
	 * Sets the check session iframe.
	 *
	 * @param check_session_iframe the new check session iframe
	 */
	public void setCheck_session_iframe(String check_session_iframe) {
		this.check_session_iframe = check_session_iframe;
	}

	/**
	 * Gets the end session endpoint.
	 *
	 * @return the end session endpoint
	 */
	public String getEnd_session_endpoint() {
		return end_session_endpoint;
	}

	/**
	 * Sets the end session endpoint.
	 *
	 * @param end_session_endpoint the new end session endpoint
	 */
	public void setEnd_session_endpoint(String end_session_endpoint) {
		this.end_session_endpoint = end_session_endpoint;
	}

	/**
	 * Gets the registration endpoint.
	 *
	 * @return the registration endpoint
	 */
	public String getRegistration_endpoint() {
		return registration_endpoint;
	}

	/**
	 * Sets the registration endpoint.
	 *
	 * @param registration_endpoint the new registration endpoint
	 */
	public void setRegistration_endpoint(String registration_endpoint) {
		this.registration_endpoint = registration_endpoint;
	}

	/**
	 * Gets the acr values supported.
	 *
	 * @return the acr values supported
	 */
	public String[] getAcr_values_supported() {
		return acr_values_supported;
	}

	/**
	 * Sets the acr values supported.
	 *
	 * @param acr_values_supported the new acr values supported
	 */
	public void setAcr_values_supported(String[] acr_values_supported) {
		this.acr_values_supported = acr_values_supported;
	}

	/**
	 * Gets the userinfo signing alg values supported.
	 *
	 * @return the userinfo signing alg values supported
	 */
	public String[] getUserinfo_signing_alg_values_supported() {
		return userinfo_signing_alg_values_supported;
	}

	/**
	 * Sets the userinfo signing alg values supported.
	 *
	 * @param userinfo_signing_alg_values_supported the new userinfo signing alg values supported
	 */
	public void setUserinfo_signing_alg_values_supported(String[] userinfo_signing_alg_values_supported) {
		this.userinfo_signing_alg_values_supported = userinfo_signing_alg_values_supported;
	}

	/**
	 * Gets the userinfo encryption alg values supported.
	 *
	 * @return the userinfo encryption alg values supported
	 */
	public String[] getUserinfo_encryption_alg_values_supported() {
		return userinfo_encryption_alg_values_supported;
	}

	/**
	 * Sets the userinfo encryption alg values supported.
	 *
	 * @param userinfo_encryption_alg_values_supported the new userinfo encryption alg values supported
	 */
	public void setUserinfo_encryption_alg_values_supported(String[] userinfo_encryption_alg_values_supported) {
		this.userinfo_encryption_alg_values_supported = userinfo_encryption_alg_values_supported;
	}

	/**
	 * Gets the userinfo encryption enc values supported.
	 *
	 * @return the userinfo encryption enc values supported
	 */
	public String[] getUserinfo_encryption_enc_values_supported() {
		return userinfo_encryption_enc_values_supported;
	}

	/**
	 * Sets the userinfo encryption enc values supported.
	 *
	 * @param userinfo_encryption_enc_values_supported the new userinfo encryption enc values supported
	 */
	public void setUserinfo_encryption_enc_values_supported(String[] userinfo_encryption_enc_values_supported) {
		this.userinfo_encryption_enc_values_supported = userinfo_encryption_enc_values_supported;
	}

	/**
	 * Gets the id token encryption alg values supported.
	 *
	 * @return the id token encryption alg values supported
	 */
	public String[] getId_token_encryption_alg_values_supported() {
		return id_token_encryption_alg_values_supported;
	}

	/**
	 * Sets the id token encryption alg values supported.
	 *
	 * @param id_token_encryption_alg_values_supported the new id token encryption alg values supported
	 */
	public void setId_token_encryption_alg_values_supported(String[] id_token_encryption_alg_values_supported) {
		this.id_token_encryption_alg_values_supported = id_token_encryption_alg_values_supported;
	}

	/**
	 * Gets the id token encryption enc values supported.
	 *
	 * @return the id token encryption enc values supported
	 */
	public String[] getId_token_encryption_enc_values_supported() {
		return id_token_encryption_enc_values_supported;
	}

	/**
	 * Sets the id token encryption enc values supported.
	 *
	 * @param id_token_encryption_enc_values_supported the new id token encryption enc values supported
	 */
	public void setId_token_encryption_enc_values_supported(String[] id_token_encryption_enc_values_supported) {
		this.id_token_encryption_enc_values_supported = id_token_encryption_enc_values_supported;
	}

	/**
	 * Gets the request object signing alg values supported.
	 *
	 * @return the request object signing alg values supported
	 */
	public String[] getRequest_object_signing_alg_values_supported() {
		return request_object_signing_alg_values_supported;
	}

	/**
	 * Sets the request object signing alg values supported.
	 *
	 * @param request_object_signing_alg_values_supported the new request object signing alg values supported
	 */
	public void setRequest_object_signing_alg_values_supported(String[] request_object_signing_alg_values_supported) {
		this.request_object_signing_alg_values_supported = request_object_signing_alg_values_supported;
	}

	/**
	 * Gets the request object encryption alg values supported.
	 *
	 * @return the request object encryption alg values supported
	 */
	public String[] getRequest_object_encryption_alg_values_supported() {
		return request_object_encryption_alg_values_supported;
	}

	/**
	 * Sets the request object encryption alg values supported.
	 *
	 * @param request_object_encryption_alg_values_supported the new request object encryption alg values supported
	 */
	public void setRequest_object_encryption_alg_values_supported(
			String[] request_object_encryption_alg_values_supported) {
		this.request_object_encryption_alg_values_supported = request_object_encryption_alg_values_supported;
	}

	/**
	 * Gets the request object encryption enc values supported.
	 *
	 * @return the request object encryption enc values supported
	 */
	public String[] getRequest_object_encryption_enc_values_supported() {
		return request_object_encryption_enc_values_supported;
	}

	/**
	 * Sets the request object encryption enc values supported.
	 *
	 * @param request_object_encryption_enc_values_supported the new request object encryption enc values supported
	 */
	public void setRequest_object_encryption_enc_values_supported(
			String[] request_object_encryption_enc_values_supported) {
		this.request_object_encryption_enc_values_supported = request_object_encryption_enc_values_supported;
	}

	/**
	 * Gets the display values supported.
	 *
	 * @return the display values supported
	 */
	public String[] getDisplay_values_supported() {
		return display_values_supported;
	}

	/**
	 * Sets the display values supported.
	 *
	 * @param display_values_supported the new display values supported
	 */
	public void setDisplay_values_supported(String[] display_values_supported) {
		this.display_values_supported = display_values_supported;
	}

	/**
	 * Gets the claim types supported.
	 *
	 * @return the claim types supported
	 */
	public String[] getClaim_types_supported() {
		return claim_types_supported;
	}

	/**
	 * Sets the claim types supported.
	 *
	 * @param claim_types_supported the new claim types supported
	 */
	public void setClaim_types_supported(String[] claim_types_supported) {
		this.claim_types_supported = claim_types_supported;
	}

	/**
	 * Gets the claims parameter supported.
	 *
	 * @return the claims parameter supported
	 */
	public Boolean getClaims_parameter_supported() {
		return claims_parameter_supported;
	}

	/**
	 * Sets the claims parameter supported.
	 *
	 * @param claims_parameter_supported the new claims parameter supported
	 */
	public void setClaims_parameter_supported(Boolean claims_parameter_supported) {
		this.claims_parameter_supported = claims_parameter_supported;
	}

	/**
	 * Gets the service documentation.
	 *
	 * @return the service documentation
	 */
	public String getService_documentation() {
		return service_documentation;
	}

	/**
	 * Sets the service documentation.
	 *
	 * @param service_documentation the new service documentation
	 */
	public void setService_documentation(String service_documentation) {
		this.service_documentation = service_documentation;
	}

	/**
	 * Gets the ui locales supported.
	 *
	 * @return the ui locales supported
	 */
	public String[] getUi_locales_supported() {
		return ui_locales_supported;
	}

	/**
	 * Sets the ui locales supported.
	 *
	 * @param ui_locales_supported the new ui locales supported
	 */
	public void setUi_locales_supported(String[] ui_locales_supported) {
		this.ui_locales_supported = ui_locales_supported;
	}

	/**
	 * Gets the introspection endpoint.
	 *
	 * @return the introspection endpoint
	 */
	public String getIntrospection_endpoint() {
		return introspection_endpoint;
	}

	/**
	 * Sets the introspection endpoint.
	 *
	 * @param introspection_endpoint the new introspection endpoint
	 */
	public void setIntrospection_endpoint(String introspection_endpoint) {
		this.introspection_endpoint = introspection_endpoint;
	}

	/**
	 * Gets the introspection async update endpoint.
	 *
	 * @return the introspection async update endpoint
	 */
	public String getIntrospection_async_update_endpoint() {
		return introspection_async_update_endpoint;
	}

	/**
	 * Sets the introspection async update endpoint.
	 *
	 * @param introspection_async_update_endpoint the new introspection async update endpoint
	 */
	public void setIntrospection_async_update_endpoint(String introspection_async_update_endpoint) {
		this.introspection_async_update_endpoint = introspection_async_update_endpoint;
	}

	/**
	 * Gets the revocation endpoint.
	 *
	 * @return the revocation endpoint
	 */
	public String getRevocation_endpoint() {
		return revocation_endpoint;
	}

	/**
	 * Sets the revocation endpoint.
	 *
	 * @param revocation_endpoint the new revocation endpoint
	 */
	public void setRevocation_endpoint(String revocation_endpoint) {
		this.revocation_endpoint = revocation_endpoint;
	}

	/**
	 * Gets the claims locales supported.
	 *
	 * @return the claims locales supported
	 */
	public String[] getClaims_locales_supported() {
		return claims_locales_supported;
	}

	/**
	 * Sets the claims locales supported.
	 *
	 * @param claims_locales_supported the new claims locales supported
	 */
	public void setClaims_locales_supported(String[] claims_locales_supported) {
		this.claims_locales_supported = claims_locales_supported;
	}

	/**
	 * Gets the request parameter supported.
	 *
	 * @return the request parameter supported
	 */
	public Boolean getRequest_parameter_supported() {
		return request_parameter_supported;
	}

	/**
	 * Sets the request parameter supported.
	 *
	 * @param request_parameter_supported the new request parameter supported
	 */
	public void setRequest_parameter_supported(Boolean request_parameter_supported) {
		this.request_parameter_supported = request_parameter_supported;
	}

	/**
	 * Gets the request uri parameter supported.
	 *
	 * @return the request uri parameter supported
	 */
	public Boolean getRequest_uri_parameter_supported() {
		return request_uri_parameter_supported;
	}

	/**
	 * Sets the request uri parameter supported.
	 *
	 * @param request_uri_parameter_supported the new request uri parameter supported
	 */
	public void setRequest_uri_parameter_supported(Boolean request_uri_parameter_supported) {
		this.request_uri_parameter_supported = request_uri_parameter_supported;
	}

	/**
	 * Gets the require request uri registration.
	 *
	 * @return the require request uri registration
	 */
	public Boolean getRequire_request_uri_registration() {
		return require_request_uri_registration;
	}

	/**
	 * Sets the require request uri registration.
	 *
	 * @param require_request_uri_registration the new require request uri registration
	 */
	public void setRequire_request_uri_registration(Boolean require_request_uri_registration) {
		this.require_request_uri_registration = require_request_uri_registration;
	}

	/**
	 * Gets the op policy uri.
	 *
	 * @return the op policy uri
	 */
	public String getOp_policy_uri() {
		return op_policy_uri;
	}

	/**
	 * Sets the op policy uri.
	 *
	 * @param op_policy_uri the new op policy uri
	 */
	public void setOp_policy_uri(String op_policy_uri) {
		this.op_policy_uri = op_policy_uri;
	}

	/**
	 * Gets the op tos uri.
	 *
	 * @return the op tos uri
	 */
	public String getOp_tos_uri() {
		return op_tos_uri;
	}

	/**
	 * Sets the op tos uri.
	 *
	 * @param op_tos_uri the new op tos uri
	 */
	public void setOp_tos_uri(String op_tos_uri) {
		this.op_tos_uri = op_tos_uri;
	}

	/**
	 * Gets the grant types supported.
	 *
	 * @return the grant types supported
	 */
	public String[] getGrant_types_supported() {
		return grant_types_supported;
	}

	/**
	 * Sets the grant types supported.
	 *
	 * @param grant_types_supported the new grant types supported
	 */
	public void setGrant_types_supported(String[] grant_types_supported) {
		this.grant_types_supported = grant_types_supported;
	}

	/**
	 * Gets the code challenge methods supported.
	 *
	 * @return the code challenge methods supported
	 */
	public String[] getCode_challenge_methods_supported() {
		return code_challenge_methods_supported;
	}

	/**
	 * Sets the code challenge methods supported.
	 *
	 * @param code_challenge_methods_supported the new code challenge methods supported
	 */
	public void setCode_challenge_methods_supported(String[] code_challenge_methods_supported) {
		this.code_challenge_methods_supported = code_challenge_methods_supported;
	}
}
