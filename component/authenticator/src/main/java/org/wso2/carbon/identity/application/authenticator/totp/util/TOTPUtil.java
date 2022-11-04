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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
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
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.ERROR_PAGE;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.TOTP_HIDE_USERSTORE_FROM_USERNAME;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE;

/**
 * TOTP Util class.
 */
public class TOTPUtil {

    private static final Log log = LogFactory.getLog(TOTPUtil.class);

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

    public static String getTOTPIssuerDisplayName(String tenantDomain, AuthenticationContext context)
            throws TOTPException {

        String issuer = null;
        if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain) ||
                Boolean.parseBoolean(getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_COMMON_ISSUER))) {
            issuer = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_ISSUER);
        } else if (context == null) {
            issuer = getIssuerFromRegistry(tenantDomain);
        } else if (context.getProperty(TOTPAuthenticatorConstants.TOTP_ISSUER) != null) {
            issuer = (String) context.getProperty(TOTPAuthenticatorConstants.TOTP_ISSUER);
        }
        if (StringUtils.isBlank(issuer)) {
            issuer = tenantDomain;
        }
        return issuer;
    }

    /**
     * Returns back the display name which will be used for the TOTP QR code URL.
     *
     * @param tenantAwareUsername   Tenant aware username
     * @return  Username
     */
    public static String getTOTPDisplayUsername(String tenantAwareUsername) {

        String hideUserStoreConfig = getTOTPParameters().get(TOTP_HIDE_USERSTORE_FROM_USERNAME);
        if (Boolean.parseBoolean(hideUserStoreConfig)) {
            return UserCoreUtil.removeDomainFromName(tenantAwareUsername);
        }
        return tenantAwareUsername;
    }

    /**
     * Get xml file data from registry and get the value for Issuer.
     *
     * @param tenantDomain
     * @return
     * @throws TOTPException On error during passing XML content or creating document builder.
     */
    private static String getIssuerFromRegistry(String tenantDomain) throws TOTPException {

        String issuer;
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            NodeList authConfigList = getAuthenticationConfigNodeList(tenantDomain, tenantID);
            issuer = getAttributeFromRegistry(authConfigList, TOTPAuthenticatorConstants.TOTP_ISSUER);
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

    private static String getAttributeFromRegistry(NodeList authConfigList, String attributeTag) {

        String attributeValue = null;
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
                            if (tagAttribute.equals(attributeTag)) {
                                attributeValue = authConfigChildElement.getTextContent();
                            }
                        }
                    }
                    break;
                }
            }
        }
        return attributeValue;
    }

    private static NodeList getAuthenticationConfigNodeList(String tenantDomain, int tenantID)
            throws RegistryException, ParserConfigurationException, SAXException, IOException {

        String xml = getAuthenticationConfigFromRegistry(tenantDomain, tenantID);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        return doc.getElementsByTagName("AuthenticatorConfig");
    }

    private static String getAuthenticationConfigFromRegistry(String tenantDomain, int tenantID)
            throws RegistryException {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        privilegedCarbonContext.setTenantId(tenantID);
        privilegedCarbonContext.setTenantDomain(tenantDomain);
        Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
        Resource resource = registry.get(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME + "/" +
                TOTPAuthenticatorConstants.APPLICATION_AUTHENTICATION_XML);
        Object content = resource.getContent();
        return new String((byte[]) content);
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
        if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
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
        if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
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
     * Get xml file data from registry and get the value for encoding method.
     *
     * @throws TOTPException On error during passing XML content or creating document builder
     */
    private static String getEncodingMethodFromRegistry(String tenantDomain, AuthenticationContext context)
            throws TOTPException {

        String encodingMethod = null;
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            NodeList authConfigList = getAuthenticationConfigNodeList(tenantDomain, tenantID);
            encodingMethod = getAttributeFromRegistry(authConfigList, TOTPAuthenticatorConstants.ENCODING_METHOD);
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
     * Get stored time step size.
     *
     * @param tenantDomain Tenant domain name.
     * @return Time step size.
     * @throws AuthenticationFailedException On Error while getting value for time step size from registry.
     */
    public static long getTimeStepSize(String tenantDomain) throws AuthenticationFailedException {

        long timeStepSize;
        if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
            timeStepSize = Long.parseLong(getTOTPParameters().get(TOTPAuthenticatorConstants.TIME_STEP_SIZE));
        } else {
            try {
                timeStepSize = getTimeStepSizeFromRegistry(tenantDomain, null);
                if (timeStepSize == -1) {
                    timeStepSize = Long.parseLong(
                            IdentityHelperUtil.getAuthenticatorParameters(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)
                                    .get(TOTPAuthenticatorConstants.TIME_STEP_SIZE));
                }
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("Cannot find the property value for timeStepSize", e);
            }
        }
        return timeStepSize;
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
     * Get stored time step size.
     *
     * @param tenantDomain Tenant domain name.
     * @return Time step size.
     * @throws TOTPException On Error while getting value for time step size from registry.
     */
    public static long getTimeStepSizeFromRegistry(String tenantDomain, AuthenticationContext context)
            throws TOTPException {

        long timeStepSize = -1;
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            NodeList authConfigList = getAuthenticationConfigNodeList(tenantDomain, tenantID);
            timeStepSize = Long.parseLong(getAttributeFromRegistry(authConfigList,
                    TOTPAuthenticatorConstants.TIME_STEP_SIZE));
        } catch (RegistryException e) {
            if (context != null) {
                context.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
                        TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
            } else {
                return -1;
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
        return timeStepSize;
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
     * Get stored windows size.
     *
     * @param tenantDomain Tenant Domain.
     * @return Window size of the totp configuration.
     * @throws AuthenticationFailedException On Error while getting value for window size from registry.
     */
    public static int getWindowSize(String tenantDomain) throws AuthenticationFailedException {

        int windowSize;
        if (TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
            windowSize = Integer.parseInt(getTOTPParameters().get(TOTPAuthenticatorConstants.WINDOW_SIZE));
        } else {
            try {
                windowSize = getWindowSizeFromRegistry(tenantDomain, null);
                if (windowSize == -1) {
                    windowSize = Integer.parseInt(
                            IdentityHelperUtil.getAuthenticatorParameters(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)
                                    .get(TOTPAuthenticatorConstants.WINDOW_SIZE));
                }
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("Cannot find the property value for windowSize", e);
            }
        }
        return windowSize;
    }

    /**
     * Get stored window size.
     *
     * @param tenantDomain Tenant domain name.
     * @return Window size.
     * @throws TOTPException On Error while getting value for window size from registry.
     */
    public static int getWindowSizeFromRegistry(String tenantDomain, AuthenticationContext context)
            throws TOTPException {

        int windowSize = -1;
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            NodeList authConfigList = getAuthenticationConfigNodeList(tenantDomain, tenantID);
            windowSize = Integer.parseInt(getAttributeFromRegistry(authConfigList,
                    TOTPAuthenticatorConstants.WINDOW_SIZE));
        } catch (RegistryException e) {
            if (context != null) {
                context.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
                        TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
            } else {
                return -1;
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
        return windowSize;
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
                TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN.equals(tenantDomain))) {
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
     * @param skey     QR code claim
     * @throws AuthenticationFailedException On error while getting value for enrolUserInAuthenticationFlow
     */
    public static void redirectToEnableTOTPReqPage(HttpServletResponse response, AuthenticationContext context,
                                                   String skey) throws AuthenticationFailedException {

        redirectToEnableTOTPReqPage(null, response, context, skey);
    }

    /**
     * Redirect the enableTOTP request page.
     *
     * @param request  The HttpServletRequest
     * @param response The HttpServletResponse
     * @param context  The AuthenticationContext
     * @param skey     QR code claim
     * @throws AuthenticationFailedException On error while getting value for enrolUserInAuthenticationFlow
     */
    public static void redirectToEnableTOTPReqPage(HttpServletRequest request, HttpServletResponse response,
                                                   AuthenticationContext context, String skey)
            throws AuthenticationFailedException {

        redirectToEnableTOTPReqPage(request, response, context, skey, null, null);
    }

    /**
     * Redirect the enableTOTP request page.
     *
     * @param request    The HttpServletRequest.
     * @param response   The HttpServletResponse.
     * @param context    The AuthenticationContext.
     * @param skey       QR code claim.
     * @param errorParam Error parameters.
     * @param retryParam Retry parameters.
     * @throws AuthenticationFailedException On error while getting value for enrolUserInAuthenticationFlow.
     */
    public static void redirectToEnableTOTPReqPage(HttpServletRequest request, HttpServletResponse response,
                                                   AuthenticationContext context, String skey, String errorParam,
                                                   String retryParam) throws AuthenticationFailedException {

        if (isEnrolUserInAuthenticationFlowEnabled(context)) {
            String multiOptionURI = getMultiOptionURIQueryParam(request);
            String queryParams = "t=" + context.getLoginTenantDomain() + "&sessionDataKey=" +
                    context.getContextIdentifier() + "&authenticators=" + TOTPAuthenticatorConstants.AUTHENTICATOR_NAME
                    + "&type=totp" + "&sp=" + Encode.forUriComponent(context.getServiceProviderName()) +
                    "&ske=" + skey + multiOptionURI;
            if (StringUtils.isNotBlank(retryParam)) {
                queryParams += retryParam;
            }
            if (StringUtils.isNotBlank(errorParam)) {
                queryParams += errorParam;
            }
            String enableTOTPReqPageUrl =
                    FrameworkUtils.appendQueryParamsStringToUrl(getEnableTOTPPage(context), queryParams);

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

    public static String getMultiOptionURIQueryParam(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? "&multiOptionURI=" + Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
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
        if (!TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain))
                && getTOTPParameters().containsKey(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String
                    .valueOf(context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL));
        } else {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(TOTPAuthenticatorConstants.LOGIN_PAGE, TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default totp login page: " + loginPage + " is used.");
            }
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
        if (!TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain))
                && getTOTPParameters().containsKey(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = getTOTPParameters().get(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String
                    .valueOf(context.getProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL));
        } else {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(TOTPAuthenticatorConstants.LOGIN_PAGE, TOTPAuthenticatorConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default error page: " + errorPage + " is used.");
            }
        }
        return errorPage;
    }

    /**
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the loginPage
     * @throws AuthenticationFailedException
     */
    public static String getTOTPLoginPage(AuthenticationContext context) throws AuthenticationFailedException {

        String loginPageFromConfig = getLoginPageFromXMLFile(context, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantQualifiedURL(loginPageFromConfig, TOTP_LOGIN_PAGE);
        } else {
            return loginPageFromConfig;
        }
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the errorPage
     * @throws AuthenticationFailedException
     */
    public static String getTOTPErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorUrlFromConfig = getErrorPageFromXMLFile(context, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantQualifiedURL(errorUrlFromConfig, ERROR_PAGE);
        } else {
            return errorUrlFromConfig;
        }
    }

    /**
     * Get the enableTOTPPage from authentication.xml file or use the error page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the enableTOTPPage
     * @throws AuthenticationFailedException
     */
    public static String getEnableTOTPPage(AuthenticationContext context) throws AuthenticationFailedException {

        String urlFromConfig = getEnableTOTPPageFromXMLFile(context, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantQualifiedURL(urlFromConfig, ENABLE_TOTP_REQUEST_PAGE);
        } else {
            return urlFromConfig;
        }
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
        if (!TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || TOTPAuthenticatorConstants.SUPER_TENANT.equals(tenantDomain))
                && getTOTPParameters().containsKey(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL)) {
            enableTOTPPage = getTOTPParameters().get(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL);
        } else if ((context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL)) != null) {
            enableTOTPPage = String
                    .valueOf(context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL));
        } else {
            enableTOTPPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(TOTPAuthenticatorConstants.LOGIN_PAGE, ENABLE_TOTP_REQUEST_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default TOTP enrollment page: " + enableTOTPPage + " is used.");
            }
        }
        return enableTOTPPage;
    }

    /**
     * Get the useEventHandlerBasedEmailSender config value from the application-authentication.xml file.
     *
     * @return Is Event Handler Based Email Sender Enabled.
     */
    public static boolean isEventHandlerBasedEmailSenderEnabled() {

        String eventHandlerBasedEmailSenderProperty = getTOTPParameters()
                .get(TOTPAuthenticatorConstants.USE_EVENT_HANDLER_BASED_EMAIL_SENDER);
        return Boolean.parseBoolean(eventHandlerBasedEmailSenderProperty);
    }

    /**
     * Get Account Lock Connector Configs.
     *
     * @param tenantDomain Tenant domain.
     * @return Account Lock Connector Configs.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = TOTPDataHolder.getInstance()
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX,
                                    TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_TIME,
                                    TOTPAuthenticatorConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO
                            }, tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new AuthenticationFailedException(
                    "Error occurred while retrieving account lock connector configuration", e);
        }
        return connectorConfigs;
    }

    /**
     * Check whether account locking is enabled for TOTP.
     *
     * @return True if account locking is enabled for TOTP.
     */
    public static boolean isAccountLockingEnabledForTotp() {

        return Boolean.parseBoolean(
                getTOTPParameters().get(TOTPAuthenticatorConstants.ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS));
    }

    /**
     * Check whether the user account is locked.
     *
     * @param userName        The username of the user.
     * @param tenantDomain    The tenant domain.
     * @param userStoreDomain The userstore domain.
     * @return True if the account is locked.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static boolean isAccountLocked(String userName, String tenantDomain, String userStoreDomain)
            throws AuthenticationFailedException {

        try {
            return TOTPDataHolder.getInstance().getAccountLockService()
                    .isAccountLocked(userName, tenantDomain, userStoreDomain);
        } catch (AccountLockServiceException e) {
            throw new AuthenticationFailedException(
                    String.format("Error while validating account lock status of user: %s.", userName), e);
        }
    }

    /**
     * Check whether the user being authenticated via a local authenticator or not.
     *
     * @param context Authentication context.
     * @return Whether the user being authenticated via a local authenticator.
     */
    public static boolean isLocalUser(AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap == null) {
            return false;
        }
        for (StepConfig stepConfig : stepConfigMap.values()) {
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.isSubjectAttributeStep() && StringUtils
                    .equals(TOTPAuthenticatorConstants.LOCAL_AUTHENTICATOR, stepConfig.getAuthenticatedIdP())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    public static AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap != null) {
            for (StepConfig stepConfig : stepConfigMap.values()) {
                AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
                if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                    authenticatedUser = new AuthenticatedUser(stepConfig.getAuthenticatedUser());
                    break;
                }
            }
        }
        return authenticatedUser;
    }

    /**
     * Checks whether sending verification code via email option is enabled.
     *
     * Ideally for TOTP we shouldn't handle fallback options at the authenticator level. This is there for sake of
     * backward compatibility. At the moment this option is a server level one.
     *
     * @return Whether sending verification code via email is enabled.
     */
    public static boolean isSendVerificationCodeByEmailEnabled() {

        String sendVerificationCodeViaEmailConfig = getTOTPParameters()
                .getOrDefault(TOTPAuthenticatorConstants.ENABLE_SEND_VERIFICATION_CODE_BY_EMAIL, "false");
        return Boolean.parseBoolean(sendVerificationCodeViaEmailConfig);
    }


    private static String getTenantQualifiedURL(String urlFromConfig,
                                                String defaultContext) throws AuthenticationFailedException {

        String context = null;
        try {
            if (isNotBlank(urlFromConfig)) {
                if (isURLRelative(urlFromConfig)) {
                    // Build tenant qualified URL using the context picked from config.
                    context = urlFromConfig;
                    return buildTenantQualifiedURL(context);
                } else {
                    // The URL picked from configs was an absolute one, we don't have a way to tenant qualify it.
                    return urlFromConfig;
                }
            } else {
                // No URL defined in configs. Build tenant qualified URL using the default context.
                context = defaultContext;
                return buildTenantQualifiedURL(context);
            }
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building tenant qualified URL for context: "
                    + context, e);
        }
    }

    private static String buildTenantQualifiedURL(String contextPath) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(contextPath).build().getAbsolutePublicURL();
    }

    private static boolean isURLRelative(String contextFromConfig) throws URISyntaxException {

        return !new URI(contextFromConfig).isAbsolute();
    }

    /**
     * Create display name for TOTP in federated Flows.
     *
     * @param context Authentication context.
     * @return TOTP display name for the federated users.
     * @throws TOTPException When handling identity provider configurations.
     */
    public static String createDisplayNameForFederatedUsers(AuthenticationContext context, String username)
            throws TOTPException {

        SequenceConfig sequenceConfig = context.getSequenceConfig();
        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

            if (authenticator instanceof FederatedApplicationAuthenticator) {
                ExternalIdPConfig externalIdPConfig;
                String externalIdPConfigName = stepConfig.getAuthenticatedIdP();
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(externalIdPConfigName, context.getTenantDomain());
                } catch (IdentityProviderManagementException e) {
                    throw new TOTPException(
                            "TOTP Display name creation failed!. Error while getting External IDP config. ", e);
                }
                if (stepConfig.isSubjectAttributeStep() && externalIdPConfig != null) {
                    Map<String, String> localClaimValues =
                            mapFederateClaimsToLocal(externalIdPConfig, stepConfig, context);
                    if (localClaimValues.size() == 0 || externalIdPConfig.getIdentityProvider() == null ||
                            externalIdPConfig.getIdentityProvider().getDefaultAuthenticatorConfig() == null ||
                            StringUtils.isBlank(externalIdPConfig.getIdentityProvider().getDefaultAuthenticatorConfig()
                                    .getDisplayName())) {
                        return null;
                    }

                    String claimValue;
                    if (localClaimValues.containsKey(TOTPAuthenticatorConstants.EMAIL_CLAIM_URL)) {
                        claimValue = localClaimValues.get(TOTPAuthenticatorConstants.EMAIL_CLAIM_URL);
                    } else if (localClaimValues.containsKey(TOTPAuthenticatorConstants.FIRST_NAME_CLAIM_URL)) {
                        claimValue = localClaimValues.get(TOTPAuthenticatorConstants.FIRST_NAME_CLAIM_URL);
                    } else {
                        claimValue =
                                localClaimValues.getOrDefault(TOTPAuthenticatorConstants.LAST_NAME_CLAIM_URL, username);
                    }

                    String idpName = externalIdPConfig.getIdentityProvider().getIdentityProviderName();
                    if (StringUtils.isNotBlank(claimValue) && StringUtils.isNotBlank(idpName)) {
                        return idpName.concat(":").concat(claimValue);
                    }
                }
            }
        }
        return null;
    }

    /**
     * Map the federated claims to local claims.
     *
     * @param externalIdPConfig External IDP configuration.
     * @param stepConfig        Step configuration.
     * @param context           Authentication context.
     * @return Hash map with local claim uri to federated user claim value.
     * @throws TOTPException When handling claim mappings.
     */
    private static Map<String, String> mapFederateClaimsToLocal(ExternalIdPConfig externalIdPConfig,
                                                                StepConfig stepConfig, AuthenticationContext context)
            throws TOTPException {

        boolean useDefaultIdpDialect = externalIdPConfig.useDefaultLocalIdpDialect();
        ApplicationAuthenticator authenticator =
                stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator();
        String idPStandardDialect = authenticator.getClaimDialectURI();
        Map<ClaimMapping, String> extAttrs = stepConfig.getAuthenticatedUser().getUserAttributes();
        Map<String, String> originalExternalAttributeValueMap =
                FrameworkUtils.getClaimMappings(extAttrs, false);
        Map<String, String> claimMapping = new HashMap<>();
        Map<String, String> localClaimValues = new HashMap<>();
        if (useDefaultIdpDialect && StringUtils.isNotBlank(idPStandardDialect)) {
            try {
                claimMapping = ClaimMetadataHandler.getInstance()
                        .getMappingsMapFromOtherDialectToCarbon(idPStandardDialect,
                                originalExternalAttributeValueMap.keySet(), context.getTenantDomain(), true);
            } catch (ClaimMetadataException e) {
                throw new TOTPException("TOTP Display name creation failed!. Error while handling claim mappings. ", e);
            }
        } else {
            ClaimMapping[] customClaimMapping = externalIdPConfig.getClaimMappings();
            if (ArrayUtils.isNotEmpty(customClaimMapping)) {
                for (ClaimMapping externalClaim : customClaimMapping) {
                    if (originalExternalAttributeValueMap.containsKey(externalClaim.getRemoteClaim().getClaimUri())) {
                        claimMapping.put(externalClaim.getLocalClaim().getClaimUri(),
                                externalClaim.getRemoteClaim().getClaimUri());
                    }
                }
            }
        }

        if (claimMapping != null) {
            for (Map.Entry<String, String> entry : claimMapping.entrySet()) {
                if (originalExternalAttributeValueMap.containsKey(entry.getValue()) &&
                        StringUtils.isNotBlank(originalExternalAttributeValueMap.get(entry.getValue()))) {
                    localClaimValues.put(entry.getKey(), originalExternalAttributeValueMap.get(entry.getValue()));
                }
            }
        }
        return localClaimValues;
    }

    /**
     * Check whether TOTP enrollment in single page enabled.
     *
     * @return true If TOTP enrollment in single page enabled. Otherwise, return false.
     */
    public static boolean isTOTPEnrollInSinglePageEnabled() {

        String isTOTPEnrollInSinglePageEnabled = getTOTPParameters()
                .getOrDefault(TOTPAuthenticatorConstants.TOTP_ENROLL_IN_SINGLE_PAGE, String.valueOf(false));
        return Boolean.parseBoolean(isTOTPEnrollInSinglePageEnabled);
    }

}
