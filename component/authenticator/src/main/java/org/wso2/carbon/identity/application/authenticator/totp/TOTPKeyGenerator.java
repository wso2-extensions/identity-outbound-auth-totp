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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.*;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
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
    public String generateTOTPKeyLocal(String username) throws TOTPException {
        //check for user store domain
        String secretkey = null;
        String qrCodeURL;
        TOTPAuthenticatorKey key = generateKey();
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

            if (userRealm != null) {
                secretkey = TOTPUtil.encrypt(key.getKey());
                String encoding = TOTPUtil.getEncodingMethod();
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, secretkey, null);
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding, null);
                getQRCodeURL(username);
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPKeyGenerator failed while trying to access userRealm for the user : " +
                    username, e);
        } catch (CryptoException e) {
            throw new TOTPException("Error when encrypting", e);
        }

        return secretkey;
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
        String encodedQRCodeURL = null;
        String encoding;

        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

            if (userRealm != null) {
                secretKey = userRealm.getUserStoreManager().getUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null);
                if (StringUtils.isEmpty(secretKey)) {
                    TOTPAuthenticatorKey key = generateKey();
                    secretKey = key.getKey();
                    encoding = TOTPUtil.getEncodingMethod();
                    userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.encrypt(secretKey), null);
                    userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding, null);
                } else {
                    secretKey = TOTPUtil.decrypt(secretKey);
                }
                String qrCodeURL = "otpauth://totp/" + tenantDomain + ":" + username + "?secret=" + secretKey + "&issuer=" + tenantDomain;
                encodedQRCodeURL = Base64.encodeBase64String(qrCodeURL.getBytes());
                userRealm.getUserStoreManager().setUserClaimValue(username, TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, encodedQRCodeURL, null);
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPKeyGenerator failed while trying to access userRealm for the user : " +
                    username, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPKeyGenerator failed while decrypting", e);
        }
        return encodedQRCodeURL;
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
     * Generate TOTPAuthenticator key
     *
     * @return TOTPAuthenticatorKey object
     */
    private TOTPAuthenticatorKey generateKey() throws TOTPException {
        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;

        if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod())) {
            encoding = TOTPKeyRepresentation.BASE64;
        }
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder gacb = new TOTPAuthenticatorConfig
                .TOTPAuthenticatorConfigBuilder()
                .setKeyRepresentation(encoding);
        TOTPAuthenticatorImpl totpAuthenticator = new TOTPAuthenticatorImpl(gacb.build());
        TOTPAuthenticatorKey key = totpAuthenticator.createCredentials();
        return key;
    }
}
