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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
/**
 * TOTP Util class.
 */
public class TOTPUtil {
	private static Log log = LogFactory.getLog(TOTPUtil.class);

	/**
	 * Get locally stored encoding method.
	 *
	 * @return
	 * @throws IdentityApplicationManagementException
	 */
	public static String getEncodingMethod() throws IdentityApplicationManagementException,
            IdentityProviderManagementException {

		FederatedAuthenticatorConfig federatedAuthenticatorConfig = getTOTPConfiguration();
		Property property = IdentityApplicationManagementUtil.
				getProperty(federatedAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.TOTP.ENCODING_METHOD);

        if (log.isDebugEnabled()) {
			log.debug("Read the encoding method from Resident Idp for tenant id : " + CarbonContext.
                    getThreadLocalCarbonContext().getTenantId());
		}

		if (TOTPAuthenticatorConstants.BASE32.equals(property.getValue())) {
            return TOTPAuthenticatorConstants.BASE32;
		}
		return TOTPAuthenticatorConstants.BASE64;
	}

    /**
     * Get locally stored time step size.
     *
     * @return
     * @throws IdentityApplicationManagementException
     */
    public static long getTimeStepSize() throws IdentityApplicationManagementException,
            IdentityProviderManagementException {

        FederatedAuthenticatorConfig federatedAuthenticatorConfig = getTOTPConfiguration();
        Property timeStep = IdentityApplicationManagementUtil.
                getProperty(federatedAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.TOTP.TIME_STEP_SIZE);
        if (log.isDebugEnabled()) {
            log.debug("Read the time step size from Resident Idp for tenant id : " + CarbonContext.
                    getThreadLocalCarbonContext().getTenantId());
        }

        return Long.parseLong(timeStep.getValue());
    }

    /**
     * Get locally stored window size.
     *
     * @return
     * @throws IdentityApplicationManagementException
     */
    public static int getWindowSize() throws IdentityApplicationManagementException,
            IdentityProviderManagementException {

        FederatedAuthenticatorConfig federatedAuthenticatorConfig = getTOTPConfiguration();
        Property window = IdentityApplicationManagementUtil.
                getProperty(federatedAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.TOTP.WINDOW_SIZE);
        if (log.isDebugEnabled()) {
            log.debug("Read the window size from Resident Idp for tenant id : " + CarbonContext.
                    getThreadLocalCarbonContext().getTenantId());
        }

        return Integer.parseInt(window.getValue());
    }

    /**
	 * Get configuration for TOTP authenticator.
	 *
	 * @return
	 * @throws IdentityApplicationManagementException
	 */
	public static FederatedAuthenticatorConfig getTOTPConfiguration() throws IdentityApplicationManagementException,
            IdentityProviderManagementException {

		String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
		IdentityProviderManager identityProviderManager = IdentityProviderManager.getInstance();

		IdentityProvider identityProvider = identityProviderManager.getResidentIdP(tenantDomain);

		return IdentityApplicationManagementUtil.
                getFederatedAuthenticator(identityProvider.getFederatedAuthenticatorConfigs(),
                        IdentityApplicationConstants.Authenticator.TOTP.NAME);
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
