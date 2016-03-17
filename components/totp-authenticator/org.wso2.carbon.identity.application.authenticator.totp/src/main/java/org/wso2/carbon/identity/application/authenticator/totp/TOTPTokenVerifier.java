/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.totp;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.KeyRepresentation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.concurrent.TimeUnit;

/**
 * TOTP Token verifier class.
 */
public class TOTPTokenVerifier {

	private static Log log = LogFactory.getLog(TOTPTokenVerifier.class);
	private static volatile TOTPTokenVerifier instance;

	private TOTPTokenVerifier() {
	}

	/**
	 * Singleton method to get instance of TOTPTokenVerifier.
	 *
	 * @return instance of TOTPTokenVerifier
	 */
	public static TOTPTokenVerifier getInstance() {
		if (instance == null) {
			synchronized (TOTPTokenVerifier.class) {
				if (instance == null) {
					instance = new TOTPTokenVerifier();
				}
			}
		}
		return instance;
	}

	/**
	 * Verify whether a given token is valid for a stored local user.
	 *
	 * @param token    TOTP Token
	 * @param username Username of the user
	 * @return true if token is valid otherwise false
	 * @throws TOTPException
	 */
	public boolean isValidTokenLocalUser(int token, String username) throws TOTPException {
		KeyRepresentation encoding = KeyRepresentation.BASE32;
        long timeStep = TOTPAuthenticatorConstants.DEFAULT_TIME_STEP_SIZE;
        int windowSize = TOTPAuthenticatorConstants.DEFAULT_WINDOW_SIZE;
		try {
			if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod())) {
				encoding = KeyRepresentation.BASE64;
			}
            timeStep = TimeUnit.SECONDS.toMillis(TOTPUtil.getTimeStepSize());
            windowSize = TOTPUtil.getWindowSize();
		} catch (IdentityApplicationManagementException e) {
			log.error("Error when reading the tenant encoding method or time step size or window size", e);
		} catch (IdentityProviderManagementException e) {
            throw new TOTPException("Error when getting the resident IDP for the user : " + username, e);
        }

        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gacb = new GoogleAuthenticatorConfig
				.GoogleAuthenticatorConfigBuilder()
				.setKeyRepresentation(encoding)
                .setWindowSize(windowSize)
                .setTimeStepSizeInMillis(timeStep);

		GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(gacb.build());
        UserRealm userRealm;
		try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

			if (userRealm != null) {
				UserStoreManager userStoreManager = userRealm.getUserStoreManager();
				String secretKey = TOTPUtil.decrypt(userStoreManager.getUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null));

                return googleAuthenticator.authorize(secretKey, token);
			} else {
				throw new TOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
						.getThreadLocalCarbonContext().getTenantDomain());
			}
		} catch (UserStoreException e) {
			throw new TOTPException("TOTPTokenVerifier failed while trying to access userRealm of the user : " +
			                        username, e);
		} catch (CryptoException e) {
            throw new TOTPException("Error while decrypting the key", e);
        }
    }

}