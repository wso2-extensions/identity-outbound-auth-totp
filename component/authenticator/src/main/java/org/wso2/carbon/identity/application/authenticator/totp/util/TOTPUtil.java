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
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
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
     * @throws TOTPException
     */
    public static String getEncodingMethod(String tenantDomain) throws Exception {
        String encodingMethod;
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            encodingMethod = getTOTPParameters().get("encodingMethod");
        } else {
            String parameter = "encodingMethod";
            encodingMethod = loadXMLFromString(parameter, tenantDomain);
        }
        if (TOTPAuthenticatorConstants.BASE32.equals(encodingMethod)) {
            return TOTPAuthenticatorConstants.BASE32;
        }
        return TOTPAuthenticatorConstants.BASE64;
    }

    /**
     * Get time step size.
     *
     * @return timeStepSize
     * @throws TOTPException
     */
    public static long getTimeStepSize(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the time step size from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Long.parseLong(getTOTPParameters().get("timeStepSize"));
        } else {
            String parameter = "timeStepSize";
            return Long.parseLong(loadXMLFromString(parameter, tenantDomain));
        }
    }

    /**
     * Get stored window size.
     *
     * @return windowSize
     * @throws TOTPException
     */
    public static int getWindowSize(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the window size from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Integer.parseInt(getTOTPParameters().get("windowSize"));
        } else {
            String parameter = "windowSize";
            return Integer.parseInt(loadXMLFromString(parameter, tenantDomain));
        }
    }

    /**
     * Check the totp enabled by admin
     *
     * @return enableTOTP
     * @throws TOTPException
     */
    public static boolean checkTOTPEnableByAdmin(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the values of enableTOTP from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Boolean.parseBoolean(getTOTPParameters().get("enableTOTP"));
        } else {
            String parameter = "enableTOTP";
            return Boolean.parseBoolean(loadXMLFromString(parameter, tenantDomain));
        }

    }

    /**
     * Get the secondary user store names.
     *
     * @param context Authentication context.
     * @throws Exception
     */
    public static String getSecondaryUserStore(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the secondary user store from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("secondaryUserstore"));
        } else {
            String parameter = "secondaryUserstore";
            return String.valueOf(loadXMLFromString(parameter, tenantDomain));
        }
    }

    /**
     * Get the federated authenticator's user attribute.
     *
     * @param context Authentication context.
     * @return user attribute
     * @throws Exception
     */
    public static String getUserAttribute(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the user attribute from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("userAttribute"));
        } else {
            String parameter = "userAttribute";
            return String.valueOf(loadXMLFromString(parameter, tenantDomain));
        }
    }

    /**
     * Get usecase type which is used to get username
     *
     * @param context Authentication context.
     * @return usecase type (local, association, userAttribute, subjectUri)
     * @throws Exception
     */
    public static String getUsecase(AuthenticationContext context) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Read the usecase Type from properties file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return String.valueOf(getTOTPParameters().get("usecase"));
        } else {
            String parameter = "usecase";
            return String.valueOf(loadXMLFromString(parameter, tenantDomain));
        }
    }

    /**
     * Get xml file data from registry
     *
     * @throws Exception
     */
    public static String getRegistry(String tenantDomain) throws Exception {
//        CarbonContext corbonContext = CarbonContext.getThreadLocalCarbonContext();
//        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        String xmlContent;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantID);
            privilegedCarbonContext.setTenantDomain(tenantDomain);
            try {
                Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
                Resource resource = registry.get(TOTPAuthenticatorConstants.REGISTRY_PATH);
                Object content = resource.getContent();
                xmlContent = new String((byte[]) content);
                return xmlContent;
            } catch (RegistryException e) {
                throw new RegistryException("Error when getting a resource in the path");
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Covert string type of xml content to xml document.
     *
     * @throws Exception
     */
    public static String loadXMLFromString(String parameter, String tenantDomain) throws Exception {
        String parameterValue = null;
        String xml = getRegistry(tenantDomain);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        NodeList authConfigList = doc.getElementsByTagName("AuthenticatorConfig");
        for (int authconfigIndex = 0; authconfigIndex < authConfigList.getLength(); authconfigIndex++) {
            Node authConfigNode = authConfigList.item(authconfigIndex);
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
                            if (tagAttribute.equals(parameter)) {
                                parameterValue = authConfigChildElement.getTextContent();
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
        return parameterValue;
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
