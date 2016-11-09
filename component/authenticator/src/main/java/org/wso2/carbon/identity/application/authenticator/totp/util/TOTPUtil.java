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
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;

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
        if (log.isDebugEnabled()) {
            log.debug("Read the user encoding method value from application authentication xml file");
        }
        String encodingMethods = null;
        Object getPropertiesFromLocal;
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            encodingMethods = String.valueOf(IdentityHelperUtil.getAuthenticatorParameters(context
                    .getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
                    .get(TOTPAuthenticatorConstants.ENCODING_METHOD));
        } else {
            getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                encodingMethods = context.getProperty(TOTPAuthenticatorConstants.ENCODING_METHOD).toString();
            } else {
                encodingMethods = String.valueOf(IdentityHelperUtil
                        .getAuthenticatorParameters(context
                                .getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
                        .get(TOTPAuthenticatorConstants.ENCODING_METHOD));
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
            log.debug("Read the user Time Step Size value from application authentication xml file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Long.parseLong(IdentityHelperUtil
                    .getAuthenticatorParameters(context
                            .getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
                    .get(TOTPAuthenticatorConstants.TIME_STEP_SIZE));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return Long.parseLong(context.getProperty(TOTPAuthenticatorConstants.TIME_STEP_SIZE).toString());
            }
            return Long.parseLong(IdentityHelperUtil
                    .getAuthenticatorParameters(context
                            .getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
                    .get(TOTPAuthenticatorConstants.TIME_STEP_SIZE));
        }
    }

    /**
     * Get stored window size.
     *
     * @return windowSize
     */
    public static int getWindowSize(AuthenticationContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Read the user window size value from application authentication xml file");
        }
        String tenantDomain = context.getTenantDomain();
        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            return Integer.parseInt(IdentityHelperUtil
                    .getAuthenticatorParameters(context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION)
                            .toString()).get(TOTPAuthenticatorConstants.WINDOW_SIZE));
        } else {
            Object getPropertiesFromLocal = context.getProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_REGISTRY);
            if (getPropertiesFromLocal == null) {
                return Integer.parseInt(context.getProperty(TOTPAuthenticatorConstants.WINDOW_SIZE).toString());
            }
            return Integer.parseInt(IdentityHelperUtil
                    .getAuthenticatorParameters(context
                            .getProperty(TOTPAuthenticatorConstants.AUTHENTICATION).toString())
                    .get(TOTPAuthenticatorConstants.WINDOW_SIZE));
        }
    }
}