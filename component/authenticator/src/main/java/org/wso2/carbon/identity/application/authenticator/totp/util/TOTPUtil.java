/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp.util;

import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

/**
 * TOTP Util class.
 */
public class TOTPUtil {
	private static Log log = LogFactory.getLog(TOTPUtil.class);

	/**
	 * Encrypt the given plain text.
	 *
	 * @param plainText The plaintext value to be encrypted and base64 encoded
	 * @return Base64 encoded string
	 * @throws CryptoException On error during encryption
	 */
	public static String encrypt(String plainText) throws CryptoException {
		return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(plainText.getBytes(Charsets.UTF_8));
	}

	/**
	 * Decrypt the given cipher text.
	 *
	 * @param cipherText The string which needs to be decrypted
	 * @return Base64 decoded string
	 * @throws CryptoException On an error during decryption
	 */
	public static String decrypt(String cipherText) throws CryptoException {
		return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(cipherText), Charsets.UTF_8);
	}

	public static String getTOTPIssuerDisplayName(String tenantDomain) throws TOTPException {

		String issuer;
		if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain) ||
				Boolean.parseBoolean(getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_COMMON_ISSUER))) {
			issuer = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_ISSUER);
		} else {
			issuer = getIssuerFromRegistry(tenantDomain);
		}

		if (StringUtils.isBlank(issuer)) {
			issuer = tenantDomain;
		}
		return issuer;
	}

	/**
	 * Get stored encoding method from AuthenticationContext.
	 *
	 * @param tenantDomain Tenant domain name
	 * @param context      AuthenticationContext
	 * @return encoding method
	 */
	public static String getEncodingMethod(String tenantDomain, AuthenticationContext context) {
		String encodingMethod = null;
		if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
			encodingMethod = String.valueOf(getTOTPParameters().get(TOTPAuthenticatorConstants.ENCODING_METHOD));
		} else {
			Object getPropertiesFromIdentityConfig = context
					.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
			if (getPropertiesFromIdentityConfig == null) {
				if (context.getProperty(TOTPAuthenticatorConstants.ENCODING_METHOD) != null) {
					encodingMethod = context.getProperty(TOTPAuthenticatorConstants.ENCODING_METHOD).toString();
				}
			} else {
				if (IdentityHelperUtil.getAuthenticatorParameters(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)
						.get(TOTPAuthenticatorConstants.ENCODING_METHOD) != null) {
					encodingMethod = String.valueOf(
							IdentityHelperUtil.getAuthenticatorParameters(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)
									.get(TOTPAuthenticatorConstants.ENCODING_METHOD));
				}
			}
		}
		if (TOTPAuthenticatorConstants.BASE64.equals(encodingMethod)) {
			return TOTPAuthenticatorConstants.BASE64;
		}
		return TOTPAuthenticatorConstants.BASE32;
	}

	/**
	 * Get stored encoding method.
	 *
	 * @param tenantDomain Tenant domain name
	 * @return encoding method
	 * @throws AuthenticationFailedException On Error while getting value for encodingMethods from registry
	 */
	public static String getEncodingMethod(String tenantDomain) throws AuthenticationFailedException {
		String encodingMethod;
		if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
			encodingMethod = String.valueOf(getTOTPParameters().get(TOTPAuthenticatorConstants.ENCODING_METHOD));
		} else {
			try {
				encodingMethod = getEncodingMethodFromRegistry(tenantDomain, null);
				if (StringUtils.isEmpty(encodingMethod)) {
					encodingMethod = String.valueOf(
							IdentityHelperUtil.getAuthenticatorParameters(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)
									.get(TOTPAuthenticatorConstants.ENCODING_METHOD));
				}
			} catch (TOTPException e) {
				throw new AuthenticationFailedException("Cannot find the property value for encodingMethod", e);
			}
		}
		if (TOTPAuthenticatorConstants.BASE64.equals(encodingMethod)) {
			return TOTPAuthenticatorConstants.BASE64;
		}
		return TOTPAuthenticatorConstants.BASE32;
	}

	/**
	 * Get parameter values from local file.
	 */
	private static Map<String, String> getTOTPParameters() {
		AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
				.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
		return authConfig.getParameterMap();
	}

	/**
	 * Get xml file data from registry and get the value for Issuer.
	 *
	 * @throws TOTPException On error during passing XML content or creating document builder
	 */
	private static String getIssuerFromRegistry(String tenantDomain)
			throws TOTPException {

		String issuer = null;
		int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
		try {
			PrivilegedCarbonContext.startTenantFlow();
			PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
			privilegedCarbonContext.setTenantId(tenantID);
			privilegedCarbonContext.setTenantDomain(tenantDomain);
			Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
			Resource resource = registry.get(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME + "/" +
					TOTPAuthenticatorConstants.APPLICATION_AUTHENTICATION_XML);
			Object content = resource.getContent();
			String xml = new String((byte[]) content);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
			NodeList authConfigList = doc.getElementsByTagName("AuthenticatorConfig");
			for (int authConfigIndex = 0; authConfigIndex < authConfigList.getLength(); authConfigIndex++) {
				Node authConfigNode = authConfigList.item(authConfigIndex);
				if (authConfigNode.getNodeType() == Node.ELEMENT_NODE) {
					Element authConfigElement = (Element) authConfigNode;
					String AuthConfig = authConfigElement.getAttribute(TOTPAuthenticatorConstants.NAME);
					if (AuthConfig.equals(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
						NodeList AuthConfigChildList = authConfigElement.getChildNodes();
						for (int j = 0; j < AuthConfigChildList.getLength(); j++) {
							Node authConfigChildNode = AuthConfigChildList.item(j);
							if (authConfigChildNode.getNodeType() == Node.ELEMENT_NODE) {
								Element authConfigChildElement = (Element) authConfigChildNode;
								String tagAttribute = AuthConfigChildList.item(j).getAttributes()
										.getNamedItem(TOTPAuthenticatorConstants.NAME).getNodeValue();
								if (tagAttribute.equals(TOTPAuthenticatorConstants.TOTP_ISSUER)) {
									issuer = authConfigChildElement.getTextContent();
								}
							}
						}
						break;
					}
				}
			}
		} catch (RegistryException e) {
			//Default to tenant domain name on registry exception.
			issuer = tenantDomain;
		} catch (SAXException e) {
			throw new TOTPException("Error while parsing the content as XML", e);
		} catch (ParserConfigurationException e) {
			throw new TOTPException("Error while creating new Document Builder", e);
		} catch (IOException e) {
			throw new TOTPException("Error while parsing the content as XML via ByteArrayInputStream", e);
		} finally {
			PrivilegedCarbonContext.endTenantFlow();
		}
		return issuer;
	}

	/**
	 * Get xml file data from registry and get the value for encoding method.
	 *
	 * @throws TOTPException On error during passing XML content or creating document builder
	 */
	private static String getEncodingMethodFromRegistry(String tenantDomain, AuthenticationContext context)
			throws TOTPException {
		String encodingMethod = null;
		int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
		try {
			PrivilegedCarbonContext.startTenantFlow();
			PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
			privilegedCarbonContext.setTenantId(tenantID);
			privilegedCarbonContext.setTenantDomain(tenantDomain);
			Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
			Resource resource = registry.get(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME + "/" +
					TOTPAuthenticatorConstants.APPLICATION_AUTHENTICATION_XML);
			Object content = resource.getContent();
			String xml = new String((byte[]) content);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
			NodeList authConfigList = doc.getElementsByTagName("AuthenticatorConfig");
			for (int authConfigIndex = 0; authConfigIndex < authConfigList.getLength(); authConfigIndex++) {
				Node authConfigNode = authConfigList.item(authConfigIndex);
				if (authConfigNode.getNodeType() == Node.ELEMENT_NODE) {
					Element authConfigElement = (Element) authConfigNode;
					String AuthConfig = authConfigElement.getAttribute(TOTPAuthenticatorConstants.NAME);
					if (AuthConfig.equals(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
						NodeList AuthConfigChildList = authConfigElement.getChildNodes();
						for (int j = 0; j < AuthConfigChildList.getLength(); j++) {
							Node authConfigChildNode = AuthConfigChildList.item(j);
							if (authConfigChildNode.getNodeType() == Node.ELEMENT_NODE) {
								Element authConfigChildElement = (Element) authConfigChildNode;
								String tagAttribute = AuthConfigChildList.item(j).getAttributes()
										.getNamedItem(TOTPAuthenticatorConstants.NAME).getNodeValue();
								if (tagAttribute.equals(TOTPAuthenticatorConstants.ENCODING_METHOD)) {
									encodingMethod = authConfigChildElement.getTextContent();
								}
							}
						}
						break;
					}
				}
			}
		} catch (RegistryException e) {
			if (context != null) {
				context.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
						TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
			} else {
				return "";
			}
		} catch (SAXException e) {
			throw new TOTPException("Error while parsing the content as XML", e);
		} catch (ParserConfigurationException e) {
			throw new TOTPException("Error while creating new Document Builder", e);
		} catch (IOException e) {
			throw new TOTPException("Error while parsing the content as XML via ByteArrayInputStream", e);
		} finally {
			PrivilegedCarbonContext.endTenantFlow();
		}
		return encodingMethod;
	}

	/**
	 * Get time step size.
	 *
	 * @return timeStepSize
	 */
	public static long getTimeStepSize(AuthenticationContext context) {
		if (log.isDebugEnabled()) {
			log.debug("Read the user Time Step Size value from application authentication xml file");
		}
		String tenantDomain = context.getTenantDomain();
		Object getPropertiesFromIdentityConfig = context
				.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
		if ((getPropertiesFromIdentityConfig != null || tenantDomain
				.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN))) {
			return Long.parseLong(IdentityHelperUtil.getAuthenticatorParameters(
					context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
					.get(TOTPAuthenticatorConstants.TIME_STEP_SIZE));
		} else {
			return Long.parseLong(context.getProperty(TOTPAuthenticatorConstants.TIME_STEP_SIZE).toString());
		}
	}

	/**
	 * Get window size.
	 *
	 * @return windowSize
	 */
	public static int getWindowSize(AuthenticationContext context) {
		if (log.isDebugEnabled()) {
			log.debug("Read the user window size value from application authentication xml file");
		}
		String tenantDomain = context.getTenantDomain();
		Object getPropertiesFromIdentityConfig = context
				.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);

		if ((getPropertiesFromIdentityConfig != null || tenantDomain
				.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN))) {
			return Integer.parseInt(IdentityHelperUtil.getAuthenticatorParameters(
					context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
					.get(TOTPAuthenticatorConstants.WINDOW_SIZE));
		} else {
			return Integer.parseInt(context.getProperty(TOTPAuthenticatorConstants.WINDOW_SIZE).toString());
		}
	}

	/**
	 * Get EnrolUserInAuthenticationFlow.
	 *
	 * @return true, if EnrolUserInAuthenticationFlow is enabled
	 */
	public static boolean isEnrolUserInAuthenticationFlowEnabled(AuthenticationContext context) {
		if (log.isDebugEnabled()) {
			log.debug("Read the EnrolUserInAuthenticationFlow value from application authentication xml file");
		}
		String tenantDomain = context.getTenantDomain();
		Object getPropertiesFromIdentityConfig =
				context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
		//If the config file is not in registry and the it is super tenant, getting the property from local.
		// Else getting it from context.
		if ((getPropertiesFromIdentityConfig != null ||
		     tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN))) {
			return Boolean.parseBoolean(IdentityHelperUtil.getAuthenticatorParameters(
					context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
					.get(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW));
		} else {
			return Boolean.parseBoolean((context.getProperty(
					TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW).toString()));
		}
	}

    /**
     * Redirect the enableTOTP request page.
     *
     * @param response The HttpServletResponse
     * @param context  The AuthenticationContext
     * @param skey  QR code claim
     * @throws AuthenticationFailedException On error while getting value for enrolUserInAuthenticationFlow
     */
    public static void redirectToEnableTOTPReqPage(HttpServletResponse response, AuthenticationContext context,
            String skey) throws AuthenticationFailedException {
	    redirectToEnableTOTPReqPage(null, response, context, skey);
    }

    /**
     * Redirect the enableTOTP request page.
     *
     * @param request The HttpServletRequest
     * @param response The HttpServletResponse
     * @param context  The AuthenticationContext
     * @param skey  QR code claim
     * @throws AuthenticationFailedException On error while getting value for enrolUserInAuthenticationFlow
     */
	public static void redirectToEnableTOTPReqPage(HttpServletRequest request, HttpServletResponse response,
			AuthenticationContext context,
			String skey) throws AuthenticationFailedException {
		if (isEnrolUserInAuthenticationFlowEnabled(context)) {
			String multiOptionURI = "";
			if (request != null) {
                multiOptionURI = request.getParameter("multiOptionURI");
                multiOptionURI = multiOptionURI != null ? "&multiOptionURI=" + Encode.forUriComponent(multiOptionURI)
                        : "";
            }
			String enableTOTPReqPageUrl = getEnableTOTPPage(context) +
					("?sessionDataKey=" + context.getContextIdentifier()) +
					"&authenticators=" +
					TOTPAuthenticatorConstants.AUTHENTICATOR_NAME +
					"&type=totp" + "&ske=" + skey + multiOptionURI;
			try {
				response.sendRedirect(enableTOTPReqPageUrl);
			} catch (IOException e) {
				throw new AuthenticationFailedException(
						"Error while redirecting the request to get enableTOTP " + "request page. ", e);
			}
		} else {
			throw new AuthenticationFailedException("Error while getting value for EnrolUserInAuthenticationFlow");
		}
	}

	/**
	 * Get the user realm of the logged in user.
	 *
	 * @param username the Username
	 * @return the userRealm
	 * @throws AuthenticationFailedException
	 */
	public static UserRealm getUserRealm(String username) throws AuthenticationFailedException {
		UserRealm userRealm = null;
		try {
			if (username != null) {
				String tenantDomain = MultitenantUtils.getTenantDomain(username);
				int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
				RealmService realmService = TOTPDataHolder.getInstance().getRealmService();
				userRealm = realmService.getTenantUserRealm(tenantId);
			}
		} catch (UserStoreException e) {
			throw new AuthenticationFailedException("Cannot find the user realm for the username: " + username, e);
		}
		return userRealm;
	}

	/**
	 * Get the login page url from the application-authentication.xml file.
	 *
	 * @param context           the AuthenticationContext
	 * @param authenticatorName the name of the authenticator
	 * @return loginPage
	 * @throws AuthenticationFailedException
	 */
	public static String getLoginPageFromXMLFile(AuthenticationContext context, String authenticatorName)
			throws AuthenticationFailedException {
		Object propertiesFromLocal = null;
		String loginPage = null;
		String tenantDomain = context.getTenantDomain();
		if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT)) {
			propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
		}
		if ((propertiesFromLocal != null || tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT))
				&& getTOTPParameters().containsKey(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL)) {
			loginPage = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL);
		} else if ((context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
			loginPage = String
					.valueOf(context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL));
		}
		return loginPage;
	}

	/**
	 * Get the error page url from the application-authentication.xml file.
	 *
	 * @param context           the AuthenticationContext
	 * @param authenticatorName the name of the authenticator
	 * @return errorPage
	 * @throws AuthenticationFailedException
	 */
	public static String getErrorPageFromXMLFile(AuthenticationContext context, String authenticatorName)
			throws AuthenticationFailedException {
		Object propertiesFromLocal = null;
		String errorPage = null;
		String tenantDomain = context.getTenantDomain();
		if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT)) {
			propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
		}
		if ((propertiesFromLocal != null || tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT))
				&& getTOTPParameters().containsKey(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
			errorPage = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL);
		} else if ((context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
			errorPage = String
					.valueOf(context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL));
		}
		return errorPage;
	}

	/**
	 * Get the enableTOTPPage from authentication.xml file or use the error page from constant file.
	 *
	 * @param context the AuthenticationContext
	 * @return the enableTOTPPage
	 * @throws AuthenticationFailedException
	 */
	private static String getEnableTOTPPage(AuthenticationContext context) throws AuthenticationFailedException {
		String enableTOTPPage = TOTPUtil
				.getEnableTOTPPageFromXMLFile(context, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
		if (StringUtils.isEmpty(enableTOTPPage)) {
			enableTOTPPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
					.replace(TOTPAuthenticatorConstants.LOGIN_PAGE,
							TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
			if (log.isDebugEnabled()) {
				log.debug("Default authentication endpoint context is used");
			}
		}
		return enableTOTPPage;
	}

	/**
	 * Get the enable TOTP page url from the application-authentication.xml file.
	 *
	 * @param context           the AuthenticationContext
	 * @param authenticatorName the name of the authenticator
	 * @return enableTOTPPage
	 * @throws AuthenticationFailedException
	 */
	public static String getEnableTOTPPageFromXMLFile(AuthenticationContext context, String authenticatorName)
			throws AuthenticationFailedException {
		Object propertiesFromLocal = null;
		String enableTOTPPage = null;
		String tenantDomain = context.getTenantDomain();
		if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT)) {
			propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
		}
		if ((propertiesFromLocal != null || tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT))
				&& getTOTPParameters().containsKey(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL)) {
			enableTOTPPage = getTOTPParameters().get(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL);
		} else if ((context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL)) != null) {
			enableTOTPPage = String
					.valueOf(context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL));
		}
		return enableTOTPPage;
	}
}