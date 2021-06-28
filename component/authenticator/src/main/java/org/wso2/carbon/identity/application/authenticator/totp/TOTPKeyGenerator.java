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
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorKey;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
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

    /**
     * Generate TOTP secret key, encoding method and QR Code url for user.
     *
     * @param username Username of the user
     * @param refresh  Boolean type of refreshing the secret token
     * @param context  Authentication context
     * @return claims
     * @throws TOTPException when user realm is null or while decrypting the key
     */
    public static Map<String, String> generateClaims(String username, boolean refresh, AuthenticationContext context)
            throws TOTPException {

        String storedSecretKey, secretKey;
        String decryptedSecretKey = null;
        String generatedSecretKey = null;
        String encodedQRCodeURL;
        String tenantAwareUsername = null;
        Map<String, String> claims = new HashMap<>();
        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            long timeStep = getTimeStamp(context, tenantDomain);
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager().
                        getUserClaimValues(tenantAwareUsername, new String[]{
                                TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                storedSecretKey =
                        userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
                if (StringUtils.isEmpty(storedSecretKey) || refresh) {
                    TOTPAuthenticatorKey key = generateKey(tenantDomain, context);
                    generatedSecretKey = key.getKey();
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

                String issuer = TOTPUtil.getTOTPIssuerDisplayName(tenantDomain, context);
                String displayUsername = TOTPUtil.getTOTPDisplayUsername(tenantAwareUsername);
                String qrCodeURL =
                        "otpauth://totp/" + issuer + ":" + displayUsername + "?secret=" + secretKey + "&issuer=" +
                                issuer + "&period=" + timeStep;
                encodedQRCodeURL = Base64.encodeBase64String(qrCodeURL.getBytes());
                claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, encodedQRCodeURL);
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPKeyGenerator failed while trying to get the user store manager from user realm of the user : " +
                            tenantAwareUsername, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPKeyGenerator failed while decrypt the storedSecretKey ", e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException(
                    "TOTPKeyGenerator cannot find the property value for encoding method", e);
        }
        return claims;
    }

    /**
     * Generate TOTP secret key for federated user, encoding method and QR Code url for user.
     *
     * @param username        Username of the user.
     * @param context         Authentication context.
     * @return Generated TOTP related claims of federated user.
     * @throws TOTPException when user realm is null or while decrypting the key
     */
    public static Map<String, String> generateClaimsForFedUser(String username, String tenantDomain,
                                                               AuthenticationContext context)
            throws TOTPException {

        String secretKey;
        String encodedQRCodeURL;
        Map<String, String> claims = new HashMap<>();
        long timeStep = getTimeStamp(context, tenantDomain);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        try {
            TOTPAuthenticatorKey key = generateKey(tenantDomain, context);
            secretKey = key.getKey();
            claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                    TOTPUtil.encrypt(secretKey));

            String issuer = TOTPUtil.getTOTPIssuerDisplayName(tenantDomain, context);
            String displayUsername = TOTPUtil.getTOTPDisplayUsername(tenantAwareUsername);
            String qrCodeURL =
                    "otpauth://totp/" + issuer + ":" + displayUsername + "?secret=" + secretKey + "&issuer=" +
                            issuer + "&period=" + timeStep;
            encodedQRCodeURL = Base64.encodeBase64String(qrCodeURL.getBytes());
            claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, encodedQRCodeURL);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPKeyGenerator failed while decrypt the storedSecretKey ", e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException(
                    "TOTPKeyGenerator cannot find the property value for encoding method", e);
        }
        return claims;
    }

    private static long getTimeStamp(AuthenticationContext context, String tenantDomain) throws TOTPException {

        long timeStep;
        try {
            if (context == null) {
                timeStep = TOTPUtil.getTimeStepSize(tenantDomain);
            } else {
                timeStep = TOTPUtil.getTimeStepSize(context);
            }
        } catch (AuthenticationFailedException e) {
            throw new TOTPException(
                    "TOTPKeyGenerator cannot get stored time step size", e);
        }
        return timeStep;
    }

    /**
     * Generate TOTP secret key, encoding method and QR Code url for user.
     *
     * @param username Username of the user
     * @param refresh  Boolean type of refreshing the secret token
     * @return claims
     * @throws TOTPException when user realm is null or while decrypting the key
     */
    public static Map<String, String> generateClaims(String username, boolean refresh) throws TOTPException {

        return generateClaims(username, refresh, null);
    }

    /**
     * Add TOTP secret key, encoding method and retrieve QR Code url for user.
     *
     * @param claims   Map with the TOTP claims
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
            throw new TOTPException("TOTPKeyGenerator failed while trying to access user store manager for the user : "
                    + tenantAwareUsername, e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("TOTPKeyGenerator cannot get the user realm for the user", e);
        }
        return qrCodeURL;
    }

    /**
     * Add TOTP secret key, encoding method and retrieve QR Code url for user.
     *
     * @param claims   Map with the TOTP claims
     * @param username Username of the user
     * @return QR code URL
     * @throws TOTPException when user realm is null or while decrypting the key
     */
    public static String addTOTPClaimsAndRetrievingQRCodeURL(Map<String, String> claims, String username)
            throws TOTPException {

        return addTOTPClaimsAndRetrievingQRCodeURL(claims, username, null);
    }

    /**
     * Remove the stored secret key and encoding method from user claim.
     *
     * @param username username of the user
     * @return true if successfully resetting the claims, false otherwise
     * @throws TOTPException                 when user realm is null for given tenant domain
     * @throws AuthenticationFailedException when user realm is null for given user
     */
    public static boolean resetLocal(String username) throws TOTPException, AuthenticationFailedException {

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
            throw new TOTPException("Can not find the user realm for the user : " + username, e);
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

    /**
     * Generate TOTPAuthenticator key.
     *
     * @param tenantDomain Tenant domain
     * @return TOTPAuthenticatorKey when user realm is null or decrypt the secret key
     * @throws AuthenticationFailedException when tenantDomain is not specified
     */
    public static TOTPAuthenticatorKey generateKey(String tenantDomain) throws AuthenticationFailedException {

        return generateKey(tenantDomain, null);
    }
}
