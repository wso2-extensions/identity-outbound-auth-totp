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

package org.wso2.carbon.identity.application.authenticator.totp;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.*;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * TOTP key generator class.
 *
 * @since 2.0.3
 */
public class TOTPKeyGenerator {

	private static Log log = LogFactory.getLog(TOTPKeyGenerator.class);

	/**
	 * Generate TOTP secret key, encoding method and QR Code url for user.
	 *
	 * @param username Username of the user
	 * @param refresh  Boolean type of refreshing the secret token
	 * @param context  Authentication context
	 * @return claims
	 * @throws TOTPException when user realm is null or while decrypting the key
	 */
	public static Map<String, String> generateClaims(String username, boolean refresh,
			AuthenticationContext context) throws TOTPException {
		String storedSecretKey, secretKey;
		String decryptedSecretKey = null;
		String generatedSecretKey = null;
		String encodedQRCodeURL;
		String tenantAwareUsername = null;
		Map<String, String> claims = new HashMap<>();
		String encoding;
		try {
			UserRealm userRealm = TOTPUtil.getUserRealm(username);
			String tenantDomain = MultitenantUtils.getTenantDomain(username);
			tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
			if (userRealm != null) {
				Map<String, String> userClaimValues = userRealm.getUserStoreManager().
						getUserClaimValues(tenantAwareUsername, new String[] {
								TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL }, null);
				storedSecretKey =
						userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
				if (StringUtils.isEmpty(storedSecretKey) || refresh) {
					TOTPAuthenticatorKey key = generateKey(tenantDomain, context);
					generatedSecretKey = key.getKey();
					if (context == null) {
						encoding = TOTPUtil.getEncodingMethod(tenantDomain);
					} else {
						encoding = TOTPUtil.getEncodingMethod(tenantDomain, context);
					}
					claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
					           TOTPUtil.encrypt(generatedSecretKey));
				} else {
					decryptedSecretKey = TOTPUtil.decrypt(storedSecretKey);
				}
				if (StringUtils.isNotEmpty(generatedSecretKey)) {
					secretKey = generatedSecretKey;
				} else {
					secretKey = decryptedSecretKey;
				}
				String qrCodeURL =
						"otpauth://totp/" + tenantDomain + ":" + tenantAwareUsername + "?secret=" +
						secretKey +
						"&issuer=" + tenantDomain;
				encodedQRCodeURL = Base64.encodeBase64String(qrCodeURL.getBytes());
				claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, encodedQRCodeURL);
			}
		} catch (UserStoreException e) {
            String msg = "TOTPKeyGenerator failed while trying to get the user store manager "
                    + "from user realm of the user : " + tenantAwareUsername;
            log.error(msg, e);
			throw new TOTPException(msg, e);
		} catch (CryptoException e) {
            String msg = "TOTPKeyGenerator failed while decrypt the storedSecretKey ";
            log.error(msg, e);
            throw new TOTPException(msg, e);
		} catch (AuthenticationFailedException e) {
            String msg = "TOTPKeyGenerator cannot find the property value for encoding method";
            log.error(msg, e);
            throw new TOTPException(msg, e);
		}
		return claims;
	}

	/**
	 * Add TOTP secret key, encoding method and retrieve QR Code url for user.
	 *
	 * @param claims  Map with the TOTP claims
	 * @param username Username of the user
	 * @param context  Authentication context
	 * @return QR code URL
	 * @throws TOTPException when user realm is null or while decrypting the key
	 */
	public static String addTOTPClaimsAndRetrievingQRCodeURL(Map<String, String> claims, String username,
			AuthenticationContext context) throws TOTPException {
		String tenantAwareUsername = null;
		String qrCodeURL = claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
		try {
			UserRealm userRealm = TOTPUtil.getUserRealm(username);
			if (userRealm != null) {
				tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
				claims.remove(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
				userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);
			}
		} catch (UserStoreException e) {
            String msg = "TOTPKeyGenerator failed while trying to access user store manager for the user : "
                    + tenantAwareUsername;
            log.error(msg, e);
            throw new TOTPException(msg, e);
		} catch (AuthenticationFailedException e) {
            String msg = "TOTPKeyGenerator cannot get the user realm for the user";
            log.error(msg, e);
            throw new TOTPException(msg, e);
		}
		return qrCodeURL;
	}

	/**
	 * Remove the stored secret key and encoding method from user claim.
	 *
	 * @param username username of the user
	 * @return true if successfully resetting the claims, false otherwise
	 * @throws TOTPException                 when user realm is null for given tenant domain
	 * @throws AuthenticationFailedException when user realm is null for given user
	 */
	public static boolean resetLocal(String username)
			throws TOTPException, AuthenticationFailedException {
		try {
			String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
			UserRealm userRealm = TOTPUtil.getUserRealm(username);
			Map<String, String> claims = new HashMap<>();
			if (userRealm != null) {
				claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "");
				userRealm.getUserStoreManager()
				         .setUserClaimValues(tenantAwareUsername, claims, null);
				return true;
			} else {
				throw new TOTPException(
						"Can not find the user realm for the given tenant domain : " +
						MultitenantUtils.getTenantDomain(username));
			}
		} catch (UserStoreException e) {
            String msg = "Can not find the user realm for the user : " + username;
            log.error(msg, e);
            throw new TOTPException(msg, e);
		}
	}

	/**
	 * Generate TOTPAuthenticator key.
	 *
	 * @param context      Authentication context
	 * @param tenantDomain Tenant domain
	 * @return TOTPAuthenticatorKey when user realm is null or decrypt the secret key
	 * @throws AuthenticationFailedException when tenantDomain is not specified
	 */
	public static TOTPAuthenticatorKey generateKey(String tenantDomain, AuthenticationContext context)
			throws AuthenticationFailedException {
		TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
		String encodingMethod;
		if (context == null) {
			encodingMethod = TOTPUtil.getEncodingMethod(tenantDomain);
		} else {
			encodingMethod = TOTPUtil.getEncodingMethod(tenantDomain, context);
		}
		if (TOTPAuthenticatorConstants.BASE64.equals(encodingMethod)) {
			encoding = TOTPKeyRepresentation.BASE64;
		}
		TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder configBuilder =
				new TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder()
						.setKeyRepresentation(encoding);
		TOTPAuthenticatorCredentials totpAuthenticator =
				new TOTPAuthenticatorCredentials(configBuilder.build());
		return totpAuthenticator.createCredentials();
	}
}
