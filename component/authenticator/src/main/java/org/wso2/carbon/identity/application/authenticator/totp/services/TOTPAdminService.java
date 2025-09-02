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
package org.wso2.carbon.identity.application.authenticator.totp.services;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPKeyGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorKey;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * This class is used to initiate, reset the TOTP and refresh the secret key.
 *
 * @since 2.0.3
 */
public class TOTPAdminService {

    private static final Log log = LogFactory.getLog(TOTPAdminService.class);
    private static final String DEFAULT_USER_UPDATE_PERMISSION = "/permission/admin/manage/identity/usermgt/update";
    private static final String SELF_OPERATIONS_ENABLED = "AdminServices.TOTPAdminService.SelfOperations.Enabled";
    private static final String SERVICE_PERMISSION = "AdminServices.TOTPAdminService.Permission";

    /**
     * Generate TOTP Token for a given user.
     *
     * @param username Username of the user
     * @param context  Authentication context
     * @return Encoded QR Code URL.
     * @throws TOTPException when could not find the user
     */
    public String initTOTP(String username, AuthenticationContext context) throws TOTPException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }

        Map<String, String> claims = TOTPKeyGenerator.generateClaims(username, false, context);
        return TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
    }

    /**
     * Generate TOTP secret for a given user and will be saved in http://wso2.org/claims/identity/verifySecretkey claim.
     *
     * @param username Username of the user
     * @return Encoded QR Code URL.
     * @throws TOTPException
     */
    public String generateSecret(String username) throws TOTPException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }

        Map<String, String> claims = TOTPKeyGenerator.generateClaims(username, false);

        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            if (userRealm != null) {
                Map<String, String> claimsToPersist = new HashMap<>();
                claimsToPersist.put(TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL,
                        claims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL));
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claimsToPersist, null);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Couldn't retrieve the user realm successfully. User realm is null for user: " + username);
                }
                throw new TOTPException("Couldn't retrieve the user realm successfully.");
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "Failed to access user store manager to store secret key for the user: " + tenantAwareUsername, e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("Error while retrieving the user realm for the user: " + tenantAwareUsername, e);
        }

        return claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    /**
     * Enable the TOTP for the given user. OTP will be validated against the secret saved in
     * http://wso2.org/claims/identity/verifySecretkey claim and if successful, secret is moved to
     * http://wso2.org/claims/identity/secretkey claim.
     *
     * @param username         Username of the user
     * @param verificationCode verification code generated from the secret issued with {@link #generateSecret(String)}
     * @return if TOTP enabling is successful or not.
     * @throws TOTPException
     */
    public boolean enableTOTP(String username, int verificationCode) throws TOTPException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }
        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            if (userRealm != null) {
                String encryptedSecretKey;

                Map<String, String> userClaimValues = userRealm.getUserStoreManager().
                        getUserClaimValues(tenantAwareUsername,
                                new String[]{TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL}, null);
                encryptedSecretKey = userClaimValues.get(TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL);

                if (StringUtils.isBlank(encryptedSecretKey)) {
                    throw new TOTPException("Secret key is not generated yet.");
                }

                boolean validationResult = validateTOTP(username, verificationCode,
                        TOTPUtil.decryptSecret(encryptedSecretKey), null);
                if (!validationResult) {
                    return false;
                }

                Map<String, String> claims = new HashMap<>();
                claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, encryptedSecretKey);
                claims.put(TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL, "");
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);

            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Couldn't retrieve the user realm successfully. User realm is null for user: " + username);
                }
                return false;
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "Failed to access user store manager to store secret key for the user: " + tenantAwareUsername, e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("Error while retrieving the user realm for the user: " + tenantAwareUsername, e);
        } catch (CryptoException e) {
            throw new TOTPException("Error while encrypting the secret key for user: " + tenantAwareUsername, e);
        }

        return true;
    }

    /**
     * Resets TOTP credentials of the user.
     *
     * @param username Username of the user
     * @return true, if successfully resets
     * @throws TOTPException when could not find the user
     */
    public boolean resetTOTP(String username) throws TOTPException, AuthenticationFailedException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }

        return TOTPKeyGenerator.resetLocal(username);
    }

    /**
     * Refreshes TOTP secret key of the user.
     *
     * @param username Username of the user
     * @param context  Authentication context
     * @return Encoded QR Code URL for refreshed secret key
     * @throws TOTPException when could not find the user
     */
    public String refreshSecretKey(String username, AuthenticationContext context) throws TOTPException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }

        Map<String, String> claims = TOTPKeyGenerator.generateClaims(username, true, context);
        return TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
    }

    /**
     * Retrieve the secret key of a given user.
     *
     * @param username Username of the user
     * @param context  Authentication context
     * @return Secret Key.
     * @throws TOTPException when could not find the user
     */
    @Deprecated
    public String retrieveSecretKey(String username, AuthenticationContext context) throws TOTPException {

        UserRealm userRealm;
        String tenantAwareUsername = null;
        byte[] secretKey = new byte[0];
        Map<String, String> claims = new HashMap<>();
        String encoding;
        try {
            userRealm = TOTPUtil.getUserRealm(username);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (!this.isAuthorized(tenantAwareUsername)) {
                throw new TOTPException("User is not authorized perform the operation");
            }
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager().
                        getUserClaimValues(tenantAwareUsername,
                                new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                secretKey = userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL)
                        .getBytes();
                if (secretKey.length < 1) {
                    TOTPAuthenticatorKey key = TOTPKeyGenerator.generateKey(tenantDomain, context);
                    secretKey = key.getKey().getBytes();
                    if (context == null) {
                        encoding = TOTPUtil.getEncodingMethod(tenantDomain);
                    } else {
                        encoding = TOTPUtil.getEncodingMethod(tenantDomain, context);
                    }
                    claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.encrypt(secretKey));
                    claims.put(TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding);
                    TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
                } else {
                    secretKey = TOTPUtil.decryptSecret(new String(secretKey));
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("TOTPAdminService cannot find the property value for encoding method", e);
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPAdminService failed while trying to get the user store manager from user realm of the user : "
                            + tenantAwareUsername, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPAdminService failed while decrypt the stored SecretKey.", e);
        }
        return new String(secretKey);
    }

    /**
     * Retrieve the secret key of a given user.
     *
     * @param username  Username of the user.
     * @param context   Authentication context.
     * @return          Byte array of the Secret Key.
     * @throws TOTPException when could not find the user.
     */
    public byte[] retrieveSecretKeyInByteArray(String username, AuthenticationContext context) throws TOTPException {

        UserRealm userRealm;
        String tenantAwareUsername = null;
        byte[] secretKey = new byte[0];
        Map<String, String> claims = new HashMap<>();
        String encoding;
        try {
            userRealm = TOTPUtil.getUserRealm(username);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager().
                        getUserClaimValues(tenantAwareUsername,
                                new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                secretKey = userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL)
                        .getBytes();
                if (secretKey.length < 1) {
                    TOTPAuthenticatorKey key = TOTPKeyGenerator.generateKey(tenantDomain, context);
                    secretKey = key.getKey().getBytes();
                    if (context == null) {
                        encoding = TOTPUtil.getEncodingMethod(tenantDomain);
                    } else {
                        encoding = TOTPUtil.getEncodingMethod(tenantDomain, context);
                    }
                    claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.encrypt(secretKey));
                    claims.put(TOTPAuthenticatorConstants.ENCODING_CLAIM_URL, encoding);
                    TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
                } else {
                    secretKey = TOTPUtil.decryptSecret(new String(secretKey));
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("TOTPAdminService cannot find the property value for encoding method", e);
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPAdminService failed while trying to get the user store manager from user realm of the user : "
                            + tenantAwareUsername, e);
        } catch (CryptoException e) {
            throw new TOTPException("TOTPAdminService failed while decrypt the stored SecretKey ", e);
        }
        return secretKey;
    }

    /**
     * Validates the user entered verification code.
     *
     * @param username         Username of the user.
     * @param context          Authentication context.
     * @param verificationCode OTP verification code.
     * @return whether OTP is valid or not.
     * @throws TOTPException when could not find the user.
     */
    public boolean validateTOTP(String username, AuthenticationContext context, int verificationCode) throws
            TOTPException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        if (!this.isAuthorized(tenantAwareUsername)) {
            throw new TOTPException("User is not authorized perform the operation");
        }

        byte[] secretKey = retrieveSecretKeyInByteArray(username, context);

        return validateTOTP(username, verificationCode, secretKey, context);
    }

    private boolean validateTOTP(String username, int verificationCode, byte[] secretKey, AuthenticationContext context)
            throws TOTPException {

        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String encodingMethod;
        long timeStepSize;
        int windowSize;
        try {
            if (context == null) {
                encodingMethod = TOTPUtil.getEncodingMethod(tenantDomain);
                timeStepSize = TOTPUtil.getTimeStepSize(tenantDomain);
                windowSize = TOTPUtil.getWindowSize(tenantDomain);
            } else {
                encodingMethod = TOTPUtil.getEncodingMethod(tenantDomain, context);
                timeStepSize = TOTPUtil.getTimeStepSize(context);
                windowSize = TOTPUtil.getWindowSize(context);
            }
            timeStepSize = TimeUnit.SECONDS.toMillis(timeStepSize);
            if (TOTPAuthenticatorConstants.BASE64.equals(encodingMethod)) {
                encoding = TOTPKeyRepresentation.BASE64;
            }
            TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder configBuilder =
                    new TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder()
                            .setKeyRepresentation(encoding)
                            .setTimeStepSizeInMillis(timeStepSize).setWindowSize(windowSize);
            TOTPAuthenticatorCredentials totpAuthenticator =
                    new TOTPAuthenticatorCredentials(configBuilder.build());
            if (log.isDebugEnabled()) {
                log.debug("Validating TOTP verification code for the user: " + username);
            }
            return totpAuthenticator.authorize(secretKey, verificationCode);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException("TOTPTokenVerifier cannot find the property value for encodingMethod.", e);
        }
    }

    /**
     * Check whether the authenticated user is authorized to perform the operation on the target user.
     * Authorization is successful if the authenticated user is trying to perform the operation on his own or
     * has the required permission.
     *
     * @param targetUser       user on whom the operation is being performed
     * @return true if authorized, false otherwise
     * @throws TOTPException when error occurs while checking authorization
     */
    private boolean isAuthorized(String targetUser) throws TOTPException {

        String authenticatedUsername = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int authenticatedTenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        RealmService realmService = TOTPDataHolder.getInstance().getRealmService();
        try {
            UserRealm userRealm = realmService.getTenantUserRealm(authenticatedTenantId);
            return isUserAuthorizedToPerformOperation(userRealm, authenticatedUsername, targetUser);
        } catch (UserStoreException e) {
            throw new TOTPException("Error while checking the authorization to perform the operation.", e);
        }
    }

    private static boolean isUserAuthorizedToPerformOperation(UserRealm realm, String currentUserName,
                                                              String targetUser)
            throws UserStoreException {

        String selfOperationsEnabled = (String) IdentityConfigParser.getInstance().getConfiguration().
                get(SELF_OPERATIONS_ENABLED);
        String permission = (String) IdentityConfigParser.getInstance().getConfiguration().
                get(SERVICE_PERMISSION);

        if (Boolean.parseBoolean(selfOperationsEnabled)) {
            if (StringUtils.equals(currentUserName, targetUser)) {
                if (log.isDebugEnabled()) {
                    log.debug("Self operations are enabled. Hence user: " + currentUserName +
                            " is authorized to perform the operation on himself.");
                }
                return true;
            }
        }
        if (StringUtils.isEmpty(permission)) {
            permission = DEFAULT_USER_UPDATE_PERMISSION;
            if (log.isDebugEnabled()) {
                log.debug("Permission is not configured. Hence using the default permission: " + permission);
            }
        }
        AuthorizationManager authorizer = realm.getAuthorizationManager();
        return authorizer.isUserAuthorized(currentUserName, permission, "ui.execute");
    }
}
