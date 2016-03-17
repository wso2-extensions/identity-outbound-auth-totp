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

import com.warrenstrange.googleauth.*;
import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * TOTP key generator class.
 */
public class TOTPKeyGenerator {

	private static Log log = LogFactory.getLog(TOTPKeyGenerator.class);
	private static volatile TOTPKeyGenerator instance;

	private TOTPKeyGenerator() {
	}

	/**
	 * Singleton method to get instance of TOTPKeyGenerator.
	 *
	 * @return instance of TOTPKeyGenerator Object
	 */
	public static TOTPKeyGenerator getInstance() {

		if (instance == null) {
			synchronized (TOTPKeyGenerator.class) {
				if (instance == null) {
					instance = new TOTPKeyGenerator();
				}
			}
		}
		return instance;
	}

	/**
	 * Generate TOTP secret key and QR Code url for local users.
	 *
	 * @param username username of the user
	 * @return TOTPDTO object containing secret key and QR code url.
	 * @throws TOTPException
	 */
	public TOTPDTO generateTOTPKeyLocal(String username) throws TOTPException {
		//check for user store domain
		String secretkey = null;
		String qrCodeURL;
		GoogleAuthenticatorKey key = generateKey();
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        qrCodeURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL(tenantDomain, username, key);

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

            if (userRealm != null) {
                secretkey = TOTPUtil.encrypt(key.getKey());
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, secretkey, null);
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, qrCodeURL, null);
                String encoding = TOTPUtil.getEncodingMethod();
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding, null);
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPKeyGenerator failed while trying to access userRealm for the user : " +
                                username, e);
        } catch (IdentityProviderManagementException e) {
            throw new TOTPException("Error when getting the resident IDP for the user : " + username, e);
        } catch (IdentityApplicationManagementException e) {
            throw new TOTPException("Error when getting the encoding method for the user : " + username, e);
        } catch (CryptoException e) {
            throw new TOTPException("Error when encrypting" , e);
        }

        return new TOTPDTO(secretkey, qrCodeURL);
	}

    /**
     * Generate TOTP secret key and QR Code url for local users.
     *
     * @param username username of the user
     * @return TOTPDTO object containing secret key and QR code url.
     * @throws TOTPException
     */
    public String getQRCodeURL(String username) throws TOTPException {
        //check for user store domain
        String secretKey;
        String qrCodeURL = null;

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

            if (userRealm != null) {
                secretKey = userRealm.getUserStoreManager().getUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null);
                if(StringUtils.isEmpty(secretKey)){
                    GoogleAuthenticatorKey key = generateKey();
                    secretKey = key.getKey();
                    userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,TOTPUtil.encrypt(secretKey), null);
                    String encoding = TOTPUtil.getEncodingMethod();
                    userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding, null);
                } else {
                    secretKey = TOTPUtil.decrypt(secretKey);
                }
                qrCodeURL = "otpauth://totp/" + tenantDomain + ":" + username + "?secret=" + secretKey + "&issuer=" + tenantDomain;
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, qrCodeURL, null);
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPKeyGenerator failed while trying to access userRealm for the user : " +
                    username, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPKeyGenerator failed while decrypting", e);
        } catch (IdentityProviderManagementException e) {
            throw new TOTPException("Error when getting the resident IDP for the user : " + username, e);
        } catch (IdentityApplicationManagementException e) {
            throw new TOTPException("Error when getting the encoding method for the user : " + username, e);
        }
        return qrCodeURL;
    }

	/**
	 * Remove the stored secret key , qr code url from user claims.
	 *
	 * @param username username of the user
	 * @return true if the operation is successful, false otherwise
	 * @throws TOTPException
	 */
	public boolean resetLocal(String username) throws TOTPException {

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

			if (userRealm != null) {
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, "", null);
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, "", null);
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "", null);
				return true;
			} else {
				throw new TOTPException("Can not find the user realm for the given tenant domain : " + CarbonContext.
                        getThreadLocalCarbonContext().getTenantDomain());
			}

		} catch (UserStoreException e) {
			throw new TOTPException("Can not find the user realm for the user : " + username, e);
		}
	}

	/**
	 * Generate GoogleAuthenticator key
	 *
	 * @return GoogleAuthenticatorKey object
	 */
	private GoogleAuthenticatorKey generateKey() throws TOTPException {
        KeyRepresentation encoding = KeyRepresentation.BASE32;
		try {
			if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod())) {
				encoding = KeyRepresentation.BASE64;
			}
		} catch (IdentityApplicationManagementException e) {
			throw new TOTPException("Error when reading the encoding method for tenant",e);
		} catch (IdentityProviderManagementException e) {
            throw new TOTPException("Error when getting the resident IDP" , e);
        }

        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gacb = new GoogleAuthenticatorConfig
				.GoogleAuthenticatorConfigBuilder()
				.setKeyRepresentation(encoding);
		GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(gacb.build());
		GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        return key;
	}
}
