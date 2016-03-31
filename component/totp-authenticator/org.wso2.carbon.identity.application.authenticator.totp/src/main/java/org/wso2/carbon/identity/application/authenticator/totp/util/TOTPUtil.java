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
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * TOTP Util class.
 */
public class TOTPUtil {
	private static Log log = LogFactory.getLog(TOTPUtil.class);

    /**
     * Get locally stored encoding method.
     *
     * @return encodingMethod
     * @throws TOTPException
     */
    public static String getEncodingMethod() throws TOTPException {

        Properties prop = getTOTPConfiguration();
        if (TOTPAuthenticatorConstants.BASE32.equals(prop.getProperty("encodingMethod"))) {
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
    public static long getTimeStepSize() throws TOTPException {
        Properties prop = getTOTPConfiguration();
        if (log.isDebugEnabled()) {
            log.debug("Read the time step size from properties file");
        }
        return Long.parseLong(prop.getProperty("timeStepSize"));
    }

    /**
     * Get locally stored window size.
     *
     * @return windowSize
     * @throws TOTPException
     */
    public static int getWindowSize() throws TOTPException {
        Properties prop = getTOTPConfiguration();
        if (log.isDebugEnabled()) {
            log.debug("Read the window size from properties file");
        }
        return Integer.parseInt(prop.getProperty("windowSize"));
    }

    /**
     * Get configuration for TOTP authenticator.
     *
     * @return prop
     * @throws TOTPException
     */
    public static Properties getTOTPConfiguration() throws TOTPException {
        String resourceName = TOTPAuthenticatorConstants.PROPERTIES_FILE;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties prop = new Properties();

        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        try {
            prop.load(resourceStream);
        } catch (IOException e) {
            throw new TOTPException("Can not find the file", e);
        }
        return prop;
    }

    public static String encrypt(String plainText) throws CryptoException {
        return  CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(
                plainText.getBytes(Charsets.UTF_8));
    }

    public static String decrypt(String cipherText) throws CryptoException {
        return new String(CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(
                cipherText), Charsets.UTF_8);
    }
}
