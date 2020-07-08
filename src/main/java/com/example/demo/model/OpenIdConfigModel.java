package com.example.demo.model;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
"token_endpoint",
"token_endpoint_auth_methods_supported",
"jwks_uri",
"response_modes_supported",
"subject_types_supported",
"id_token_signing_alg_values_supported",
"response_types_supported",
"scopes_supported",
"issuer",
"request_uri_parameter_supported",
"userinfo_endpoint",
"authorization_endpoint",
"http_logout_supported",
"frontchannel_logout_supported",
"end_session_endpoint",
"claims_supported",
"tenant_region_scope",
"cloud_instance_name",
"cloud_graph_host_name",
"msgraph_host",
"rbac_url"
})
public class OpenIdConfigModel {

@JsonProperty("token_endpoint")
private String tokenEndpoint;
@JsonProperty("token_endpoint_auth_methods_supported")
private List<String> tokenEndpointAuthMethodsSupported = null;
@JsonProperty("jwks_uri")
private String jwksUri;
@JsonProperty("response_modes_supported")
private List<String> responseModesSupported = null;
@JsonProperty("subject_types_supported")
private List<String> subjectTypesSupported = null;
@JsonProperty("id_token_signing_alg_values_supported")
private List<String> idTokenSigningAlgValuesSupported = null;
@JsonProperty("response_types_supported")
private List<String> responseTypesSupported = null;
@JsonProperty("scopes_supported")
private List<String> scopesSupported = null;
@JsonProperty("issuer")
private String issuer;
@JsonProperty("request_uri_parameter_supported")
private Boolean requestUriParameterSupported;
@JsonProperty("userinfo_endpoint")
private String userinfoEndpoint;
@JsonProperty("authorization_endpoint")
private String authorizationEndpoint;
@JsonProperty("http_logout_supported")
private Boolean httpLogoutSupported;
@JsonProperty("frontchannel_logout_supported")
private Boolean frontchannelLogoutSupported;
@JsonProperty("end_session_endpoint")
private String endSessionEndpoint;
@JsonProperty("claims_supported")
private List<String> claimsSupported = null;
@JsonProperty("tenant_region_scope")
private String tenantRegionScope;
@JsonProperty("cloud_instance_name")
private String cloudInstanceName;
@JsonProperty("cloud_graph_host_name")
private String cloudGraphHostName;
@JsonProperty("msgraph_host")
private String msgraphHost;
@JsonProperty("rbac_url")
private String rbacUrl;
@JsonIgnore
private Map<String, Object> additionalProperties = new HashMap<String, Object>();

@JsonProperty("token_endpoint")
public String getTokenEndpoint() {
return tokenEndpoint;
}

@JsonProperty("token_endpoint")
public void setTokenEndpoint(String tokenEndpoint) {
this.tokenEndpoint = tokenEndpoint;
}

@JsonProperty("token_endpoint_auth_methods_supported")
public List<String> getTokenEndpointAuthMethodsSupported() {
return tokenEndpointAuthMethodsSupported;
}

@JsonProperty("token_endpoint_auth_methods_supported")
public void setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
}

@JsonProperty("jwks_uri")
public String getJwksUri() {
return jwksUri;
}

@JsonProperty("jwks_uri")
public void setJwksUri(String jwksUri) {
this.jwksUri = jwksUri;
}

@JsonProperty("response_modes_supported")
public List<String> getResponseModesSupported() {
return responseModesSupported;
}

@JsonProperty("response_modes_supported")
public void setResponseModesSupported(List<String> responseModesSupported) {
this.responseModesSupported = responseModesSupported;
}

@JsonProperty("subject_types_supported")
public List<String> getSubjectTypesSupported() {
return subjectTypesSupported;
}

@JsonProperty("subject_types_supported")
public void setSubjectTypesSupported(List<String> subjectTypesSupported) {
this.subjectTypesSupported = subjectTypesSupported;
}

@JsonProperty("id_token_signing_alg_values_supported")
public List<String> getIdTokenSigningAlgValuesSupported() {
return idTokenSigningAlgValuesSupported;
}

@JsonProperty("id_token_signing_alg_values_supported")
public void setIdTokenSigningAlgValuesSupported(List<String> idTokenSigningAlgValuesSupported) {
this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
}

@JsonProperty("response_types_supported")
public List<String> getResponseTypesSupported() {
return responseTypesSupported;
}

@JsonProperty("response_types_supported")
public void setResponseTypesSupported(List<String> responseTypesSupported) {
this.responseTypesSupported = responseTypesSupported;
}

@JsonProperty("scopes_supported")
public List<String> getScopesSupported() {
return scopesSupported;
}

@JsonProperty("scopes_supported")
public void setScopesSupported(List<String> scopesSupported) {
this.scopesSupported = scopesSupported;
}

@JsonProperty("issuer")
public String getIssuer() {
return issuer;
}

@JsonProperty("issuer")
public void setIssuer(String issuer) {
this.issuer = issuer;
}

@JsonProperty("request_uri_parameter_supported")
public Boolean getRequestUriParameterSupported() {
return requestUriParameterSupported;
}

@JsonProperty("request_uri_parameter_supported")
public void setRequestUriParameterSupported(Boolean requestUriParameterSupported) {
this.requestUriParameterSupported = requestUriParameterSupported;
}

@JsonProperty("userinfo_endpoint")
public String getUserinfoEndpoint() {
return userinfoEndpoint;
}

@JsonProperty("userinfo_endpoint")
public void setUserinfoEndpoint(String userinfoEndpoint) {
this.userinfoEndpoint = userinfoEndpoint;
}

@JsonProperty("authorization_endpoint")
public String getAuthorizationEndpoint() {
return authorizationEndpoint;
}

@JsonProperty("authorization_endpoint")
public void setAuthorizationEndpoint(String authorizationEndpoint) {
this.authorizationEndpoint = authorizationEndpoint;
}

@JsonProperty("http_logout_supported")
public Boolean getHttpLogoutSupported() {
return httpLogoutSupported;
}

@JsonProperty("http_logout_supported")
public void setHttpLogoutSupported(Boolean httpLogoutSupported) {
this.httpLogoutSupported = httpLogoutSupported;
}

@JsonProperty("frontchannel_logout_supported")
public Boolean getFrontchannelLogoutSupported() {
return frontchannelLogoutSupported;
}

@JsonProperty("frontchannel_logout_supported")
public void setFrontchannelLogoutSupported(Boolean frontchannelLogoutSupported) {
this.frontchannelLogoutSupported = frontchannelLogoutSupported;
}

@JsonProperty("end_session_endpoint")
public String getEndSessionEndpoint() {
return endSessionEndpoint;
}

@JsonProperty("end_session_endpoint")
public void setEndSessionEndpoint(String endSessionEndpoint) {
this.endSessionEndpoint = endSessionEndpoint;
}

@JsonProperty("claims_supported")
public List<String> getClaimsSupported() {
return claimsSupported;
}

@JsonProperty("claims_supported")
public void setClaimsSupported(List<String> claimsSupported) {
this.claimsSupported = claimsSupported;
}

@JsonProperty("tenant_region_scope")
public String getTenantRegionScope() {
return tenantRegionScope;
}

@JsonProperty("tenant_region_scope")
public void setTenantRegionScope(String tenantRegionScope) {
this.tenantRegionScope = tenantRegionScope;
}

@JsonProperty("cloud_instance_name")
public String getCloudInstanceName() {
return cloudInstanceName;
}

@JsonProperty("cloud_instance_name")
public void setCloudInstanceName(String cloudInstanceName) {
this.cloudInstanceName = cloudInstanceName;
}

@JsonProperty("cloud_graph_host_name")
public String getCloudGraphHostName() {
return cloudGraphHostName;
}

@JsonProperty("cloud_graph_host_name")
public void setCloudGraphHostName(String cloudGraphHostName) {
this.cloudGraphHostName = cloudGraphHostName;
}

@JsonProperty("msgraph_host")
public String getMsgraphHost() {
return msgraphHost;
}

@JsonProperty("msgraph_host")
public void setMsgraphHost(String msgraphHost) {
this.msgraphHost = msgraphHost;
}

@JsonProperty("rbac_url")
public String getRbacUrl() {
return rbacUrl;
}

@JsonProperty("rbac_url")
public void setRbacUrl(String rbacUrl) {
this.rbacUrl = rbacUrl;
}

@JsonAnyGetter
public Map<String, Object> getAdditionalProperties() {
return this.additionalProperties;
}

@JsonAnySetter
public void setAdditionalProperty(String name, Object value) {
this.additionalProperties.put(name, value);
}

}