/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.xml.sax.SAXException;

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

    public static String encrypt(String plainText) throws CryptoException {
        return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(
                plainText.getBytes(Charsets.UTF_8));
    }

    public static String decrypt(String cipherText) throws CryptoException {
        return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(
                cipherText), Charsets.UTF_8);
    }

    /**
     * Get stored encoding method.
     *
     * @return encodingMethod
     */
    public static String getEncodingMethod(String tenantDomain, AuthenticationContext context) throws
            AuthenticationFailedException {
        String encodingMethods;
        Object getPropertiesFromLocal;
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            encodingMethods = String.valueOf(getTOTPParameters().get("encodingMethod"));
        } else if (context == null) {
            try {
                encodingMethods = loadXMLFromRegistry(context, tenantDomain);
                if (encodingMethods == null) {
                    encodingMethods = String.valueOf(getTOTPParameters().get("encodingMethod"));
                }
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("Cannot find the property value for encodingMethod");
            }
        } else {
            getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                encodingMethods = context.getProperty("encodingMethod").toString();
            } else {
                encodingMethods = String.valueOf(getTOTPParameters().get("encodingMethod"));
            }
        }
        if (TOTPAuthenticatorConstants.BASE32.equals(encodingMethods)) {
            return TOTPAuthenticatorConstants.BASE32;
        }
        return TOTPAuthenticatorConstants.BASE64;
    }

    /**
     * Get time step size.
     *
     * @return timeStepSize
     */
    public static long getTimeStepSize(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the time step size from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Long.parseLong(getTOTPParameters().get("timeStepSize"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return Long.parseLong(context.getProperty("timeStepSize").toString());
            }
            return Long.parseLong(getTOTPParameters().get("timeStepSize"));
        }
    }

    /**
     * Get stored window size.
     *
     * @return windowSize
     */
    public static int getWindowSize(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the window size from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Integer.parseInt(getTOTPParameters().get("windowSize"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return Integer.parseInt(context.getProperty("windowSize").toString());
            }
            return Integer.parseInt(getTOTPParameters().get("windowSize"));
        }
    }

    /**
     * Check the totp enabled by admin
     *
     * @return enableTOTP
     */
    public static boolean checkTOTPEnableByAdmin(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the values of enableTOTP from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Boolean.parseBoolean(getTOTPParameters().get("enableTOTP"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return Boolean.parseBoolean(context.getProperty("enableTOTP").toString());
            }
            return Boolean.parseBoolean(getTOTPParameters().get("enableTOTP"));
        }
    }

    /**
     * Get the secondary user store names.
     *
     * @param context Authentication context.
     */
    public static String getSecondaryUserStore(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the secondary user store from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("secondaryUserstore"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return context.getProperty("secondaryUserstore").toString();
            }
            return String.valueOf(getTOTPParameters().get("secondaryUserstore"));
        }
    }

    /**
     * Get the federated authenticator's user attribute.
     *
     * @param context Authentication context.
     * @return user attribute
     */
    public static String getUserAttribute(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the user attribute from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("userAttribute"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return context.getProperty("userAttribute").toString();
            }
            return String.valueOf(getTOTPParameters().get("userAttribute"));
        }
    }

    /**
     * Get usecase type which is used to get username
     *
     * @param context Authentication context.
     * @return usecase type (local, association, userAttribute, subjectUri)
     */
    public static String getUsecase(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the usecase Type from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("usecase"));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return context.getProperty("usecase").toString();
            }
            return String.valueOf(getTOTPParameters().get("usecase"));
        }
    }

    /**
     * Get xml file data from registry and covert string type of xml content to xml document.
     *
     * @throws TOTPException
     */
    public static String loadXMLFromRegistry(AuthenticationContext context, String tenantDomain) throws TOTPException {
        String xml, encodingMethod = null, timeStepSize = null, windowSize = null,
                enableTOTP = null, usecase = null, userAttribute = null, secondaryUserstore = null;
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantID);
            privilegedCarbonContext.setTenantDomain(tenantDomain);
            Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
            Resource resource = registry.get(TOTPAuthenticatorConstants.REGISTRY_PATH);
            Object content = resource.getContent();
            xml = new String((byte[]) content);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder;
            builder = factory.newDocumentBuilder();
            Document doc;
            doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
            NodeList authConfigList = doc.getElementsByTagName("AuthenticatorConfig");
            for (int authConfigIndex = 0; authConfigIndex < authConfigList.getLength(); authConfigIndex++) {
                Node authConfigNode = authConfigList.item(authConfigIndex);
                if (authConfigNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element authConfigElement = (Element) authConfigNode;
                    String AuthConfig = authConfigElement.getAttribute("name");
                    if (AuthConfig.equals("totp")) {
                        NodeList AuthConfigChildList = authConfigElement.getChildNodes();
                        for (int j = 0; j < AuthConfigChildList.getLength(); j++) {
                            Node authConfigChildNode = AuthConfigChildList.item(j);
                            if (authConfigChildNode.getNodeType() == Node.ELEMENT_NODE) {
                                Element authConfigChildElement = (Element) authConfigChildNode;
                                String tagAttribute = AuthConfigChildList.item(j).getAttributes().getNamedItem("name").getNodeValue();
                                if (tagAttribute.equals("encodingMethod")) {
                                    encodingMethod = authConfigChildElement.getTextContent();
                                } else if (tagAttribute.equals("timeStepSize")) {
                                    timeStepSize = authConfigChildElement.getTextContent();
                                } else if (tagAttribute.equals("windowSize")) {
                                    windowSize = authConfigChildElement.getTextContent();
                                } else if (tagAttribute.equals("enableTOTP")) {
                                    enableTOTP = authConfigChildElement.getTextContent();
                                } else if (tagAttribute.equals("usecase")) {
                                    usecase = authConfigChildElement.getTextContent();
                                } else if (tagAttribute.equals("userAttribute")) {
                                    userAttribute = authConfigChildElement.getTextContent();
                                } else {
                                    secondaryUserstore = authConfigChildElement.getTextContent();
                                }
                            }
                        }
                        break;
                    }
                }
            }
            if (context != null) {
                context.setProperty("encodingMethod", encodingMethod);
                context.setProperty("timeStepSize", timeStepSize);
                context.setProperty("windowSize", windowSize);
                context.setProperty("enableTOTP", enableTOTP);
                context.setProperty("usecase", usecase);
                context.setProperty("userAttribute", userAttribute);
                context.setProperty("secondaryUserstore", secondaryUserstore);
            }
        } catch (SAXException | ParserConfigurationException | IOException e) {
            throw new TOTPException("Cannot get the TOTP parameter values. ", e);
        } catch (RegistryException e) {
            if (context != null) {
                context.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY,
                        TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            } else {
                return "";
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return encodingMethod;
    }

    /**
     * Get parameter values from local file.
     */
    public static Map<String, String> getTOTPParameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }
}