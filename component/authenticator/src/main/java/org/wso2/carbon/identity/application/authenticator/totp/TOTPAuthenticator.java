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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.totp.dao.DAOFactory;
import org.wso2.carbon.identity.application.authenticator.totp.dao.TOTPSecretKeyDAO;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil.getMultiOptionURIQueryParam;
import static org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil.getTOTPErrorPage;
import static org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil.getTOTPLoginPage;

/**
 * Authenticator of TOTP.
 *
 * @since 2.0.3
 */
public class TOTPAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 2009231028659744926L;
    private static final Log log = LogFactory.getLog(TOTPAuthenticator.class);

    /**
     * Check whether token or action are in request.
     *
     * @param request The http servlet request
     * @return true, if token or action are not null
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        String action = request.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN);
        String enableTOTP = request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP);
        return (token != null || action != null || enableTOTP != null);
    }

    /**
     * This method is overridden to check additional condition like whether request is having
     * sendToken, token parameters, generateTOTPToken and authentication name.
     *
     * @param request  Http servlet request
     * @param response Http servlet response
     * @param context  AuthenticationContext
     * @return AuthenticatorFlowStatus
     * @throws AuthenticationFailedException User tenant domain mismatch
     * @throws LogoutFailedException         Error while checking logout request
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (request.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN) != null) {
            if (generateOTPAndSendByEmail(context)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }
        } else if (StringUtils
                .isNotEmpty(request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION)
                    .equals(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else if (request.getParameter(TOTPAuthenticatorConstants.TOKEN) == null) {
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION)
                    .equals(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate authentication request.
     *
     * @param request  The request
     * @param response The response
     * @param context  The authentication context
     * @throws AuthenticationFailedException If authenticatedUser could not be identified
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = null;
        String userId = null;
        AuthenticatedUser authenticatedUser = null;
        boolean isFederatedUser = false;
        String tenantDomain = context.getTenantDomain();
        TOTPSecretKeyDAO totpSecretKeyDAO = DAOFactory.getInstance().getTOTPSecretKeyDAO();
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil
                    .loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
        }
        String retryParam = "";
        try {
            if (!TOTPUtil.isLocalUser(context)) {
                isFederatedUser = true;
                Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    authenticatedUser = stepConfig.getAuthenticatedUser();
                    if (authenticatedUser != null && isFederatedUser(authenticatedUser) &&
                            stepConfig.isSubjectAttributeStep()) {
                        username = authenticatedUser.getUserName();
                        userId = getUserId(authenticatedUser, context, stepConfig, tenantDomain);
                        context.setProperty(TOTPAuthenticatorConstants.FEDERATED_USER_ID, userId);
                        break;
                    }
                }
            } else {
                FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
                username = String.valueOf(context.getProperty("username"));
                authenticatedUser = (AuthenticatedUser) context.getProperty("authenticatedUser");
            }
            // find the authenticated user.
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException(
                        "Authentication failed!. Cannot proceed further without identifying the user");
            }
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            boolean isTOTPEnabledFederatedUser = false;
            boolean isTOTPEnabledLocalUser = false;
            if (isFederatedUser) {
                isTOTPEnabledFederatedUser = totpSecretKeyDAO.getTOTPSecretKeyOfFederatedUser(userId) != null;
            } else {
                isTOTPEnabledLocalUser = isTOTPEnabledForLocalUser(username);
            }
            if (log.isDebugEnabled()) {
                log.debug("TOTP is enabled by user: " + username);
            }
            boolean isTOTPEnabledByAdmin = IdentityHelperUtil.checkSecondStepEnableByAdmin(context);
            if (log.isDebugEnabled()) {
                log.debug("TOTP  is enabled by admin: " + isTOTPEnabledByAdmin);
            }

            // This multi option URI is used to navigate back to multi option page to select a different
            // authentication option from TOTP pages.
            String multiOptionURI = getMultiOptionURIQueryParam(request);

            if ((isTOTPEnabledLocalUser || isTOTPEnabledFederatedUser)
                    && request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP) == null) {
                //if TOTP is enabled for the user.
                String totpLoginPageUrl = buildTOTPLoginPageURL(context, username, retryParam, multiOptionURI);
                response.sendRedirect(totpLoginPageUrl);
            } else {
                if (TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context)
                        && request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP) == null) {
                    //if TOTP is not enabled for the user and he hasn't redirected to the enrolment page yet.
                    if (log.isDebugEnabled()) {
                        log.debug("User has not enabled TOTP: " + username);
                    }
                    Map<String, String> claims;
                    if (isFederatedUser) {
                        String storedSecretKey = totpSecretKeyDAO.getTOTPSecretKeyOfFederatedUser(userId);
                        claims = TOTPKeyGenerator.generateClaimsForFedUser(username, tenantDomain, storedSecretKey,
                                false, context);
                    }
                    else{
                        claims = TOTPKeyGenerator.generateClaims(username, false, context);
                    }
                    context.setProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                            claims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL));
                    context.setProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL,
                            claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL));
                    String qrURL = claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
                    TOTPUtil.redirectToEnableTOTPReqPage(request, response, context, qrURL);
                } else if (Boolean.valueOf(request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP))) {
                    //if TOTP is not enabled for the user and user continued the enrolment.
                    context.setProperty(TOTPAuthenticatorConstants.ENABLE_TOTP, true);

                    String totpLoginPageUrl = buildTOTPLoginPageURL(context, username, retryParam, multiOptionURI);
                    response.sendRedirect(totpLoginPageUrl);
                } else {
                    if (isTOTPEnabledByAdmin) {
                        //if TOTP is not enabled for the user and admin enforces TOTP.
                        String totpErrorPageUrl = buildTOTPErrorPageURL(context, username, retryParam, multiOptionURI);
                        response.sendRedirect(totpErrorPageUrl);
                    } else {
                        //if admin does not enforces TOTP and TOTP is not enabled for the user.
                        context.setSubject(authenticatedUser);
                        StepConfig stepConfig = context.getSequenceConfig().getStepMap()
                                .get(context.getCurrentStep() - 1);
                        if (stepConfig.getAuthenticatedAutenticator()
                                .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                            context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                                    TOTPAuthenticatorConstants.BASIC);
                        } else {
                            context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                                    TOTPAuthenticatorConstants.FEDERETOR);
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    "Error when redirecting the TOTP login response, user : " + username, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException(
                    "Error when checking TOTP enabled for the user : " + username, e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(
                    "Authentication failed!. Cannot get the username from first step.", e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building TOTP page URL.", e);
        }
    }

    private String buildTOTPLoginPageURL(AuthenticationContext context, String username, String retryParam,
                                         String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName()
                + "&type=totp" + retryParam + "&username=" + username + multiOptionURI;
        String loginPage = FrameworkUtils.appendQueryParamsStringToUrl(getTOTPLoginPage(context), queryString);
        return buildAbsoluteURL(loginPage);
    }

    private String buildTOTPErrorPageURL(AuthenticationContext context, String username, String retryParam,
                                         String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName()
                + "&type=totp_error" + retryParam + "&username=" + username + multiOptionURI;
        String errorPage = FrameworkUtils.appendQueryParamsStringToUrl(getTOTPErrorPage(context), queryString);
        return buildAbsoluteURL(errorPage);
    }

    private String buildAbsoluteURL(String redirectUrl) throws URISyntaxException, URLBuilderException {

        URI uri = new URI(redirectUrl);
        if (uri.isAbsolute()) {
            return redirectUrl;
        } else {
            return ServiceURLBuilder.create().addPath(redirectUrl).build().getAbsolutePublicURL();
        }
    }

    /**
     * This method is overridden to check validation of the given token.
     *
     * @param request  The http servlet request
     * @param response The http servlet response
     * @param context  AuthenticationContext
     * @throws AuthenticationFailedException Authentication process failed for user
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        String username = authenticatedUser.toFullQualifiedUsername();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userId = (String) context.getProperty(TOTPAuthenticatorConstants.FEDERATED_USER_ID);
        validateAccountLockStatusForLocalUser(context, authenticatedUser);
        if (StringUtils.isBlank(token)) {
            handleTotpVerificationFail(context);
            throw new AuthenticationFailedException("Empty TOTP in the request. Authentication Failed for user: " +
                    username);
        }
        try {
            int tokenValue = Integer.parseInt(token);
            if (TOTPUtil.isLocalUser(context)) {
                checkTotpEnabled(context, username);
                if (!isValidTokenLocalUser(tokenValue, username, context)) {
                    handleTotpVerificationFail(context);
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed, user :  " + username);
                }
            } else {
                storeSecretKeyForFedUsers(context);
                if (!isValidTokenFederatedUser(tokenValue, userId, tenantDomain, context)) {
                    handleTotpVerificationFail(context);
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed, user :  " + username);
                }
            }
            if (StringUtils.isNotBlank(username)) {
                authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setAuthenticatedSubjectIdentifier(username);
                authenticatedUser.setUserName(UserCoreUtil.removeDomainFromName(
                        MultitenantUtils.getTenantAwareUsername(username)));
                authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
                authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(username));
                context.setSubject(authenticatedUser);
            } else {
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
            }
        } catch (NumberFormatException e) {
            handleTotpVerificationFail(context);
            throw new AuthenticationFailedException("TOTP Authentication process failed for user " + username, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException("TOTP Authentication process failed for user " + username, e);
        }
        // It reached here means the authentication was successful.
        resetTotpFailedAttempts(context);
    }

    private void checkTotpEnabled(AuthenticationContext context, String username) throws AuthenticationFailedException {

        if (context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP) != null && Boolean
                .parseBoolean(context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP).toString())) {
            //adds the claims to the profile if the user enrol and continued.
            Map<String, String> claims = new HashMap<>();
            if (context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL) != null) {
                claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                        context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL).toString());
            }
            if (context.getProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL) != null) {
                claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL,
                        context.getProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL).toString());
            }
            try {
                TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("Error while adding TOTP claims to the user : " + username, e);
            }
        }
    }

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                authenticatedUser = new AuthenticatedUser(stepConfig.getAuthenticatedUser());
                break;
            }
        }
        return authenticatedUser;
    }

    private void validateAccountLockStatusForLocalUser(AuthenticationContext context, AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        boolean isLocalUser = TOTPUtil.isLocalUser(context);
        AuthenticatedUser authenticatedUserObject =
                (AuthenticatedUser) context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER);
        String username = authenticatedUser.getUserName();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        if (isLocalUser &&
                TOTPUtil.isAccountLocked(authenticatedUserObject.getUserName(), tenantDomain, userStoreDomain)) {
            String errorMessage =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            getUserStoreAppendedName(username));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new AuthenticationFailedException(errorMessage);
        }
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get requested session ID.
     *
     * @param request The http servlet request
     * @return Requested session ID
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    /**
     * Get friendly name.
     *
     * @return Authenticator friendly name
     */
    @Override
    public String getFriendlyName() {

        return TOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get authenticator name.
     *
     * @return Authenticator name
     */
    @Override
    public String getName() {

        return TOTPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Generate TOTP token.
     *
     * @param context AuthenticationContext
     * @return true, if token is generated successfully
     */
    private boolean generateOTPAndSendByEmail(AuthenticationContext context) {

        String username = getUsernameFromContext(context);

        if (!TOTPUtil.isSendVerificationCodeByEmailEnabled()) {
            String appName = context.getServiceProviderName();
            String tenantDomain = context.getTenantDomain();
            String sessionDataKey = context.getContextIdentifier();

            String msg = "Sending verification code by email is disabled by admin. An attempt was made to send a " +
                    "verification code by email for user: %s for application: %s of %s tenant using sessionDataKey: %s";
            log.warn(String.format(msg, username, appName, tenantDomain, sessionDataKey));
            return false;
        }

        if (username == null) {
            log.error("No username found in the authentication context.");
            return false;
        } else {
            try {
                TOTPTokenGenerator.generateTOTPTokenLocal(username, context);
                if (log.isDebugEnabled()) {
                    log.debug("TOTP Token is generated");
                }
            } catch (TOTPException e) {
                log.error("Error when generating the totp token", e);
                return false;
            }
        }
        return true;
    }

    private String getUsernameFromContext(AuthenticationContext context) {

        if (context.getProperty("username") == null) {
            return null;
        }

        return context.getProperty("username").toString();
    }

    /**
     * Check whether TOTP is enabled for local user or not.
     *
     * @param username Username of the user
     * @return true, if TOTP enable for local user
     * @throws TOTPException when user realm is null or could not find user
     */
    private boolean isTOTPEnabledForLocalUser(String username)
            throws TOTPException, AuthenticationFailedException {

        UserRealm userRealm = TOTPUtil.getUserRealm(username);
        String tenantAwareUsername = null;
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                Map<String, String> UserClaimValues =
                        userRealm.getUserStoreManager().getUserClaimValues
                                (tenantAwareUsername, new String[]
                                        {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                String secretKey =
                        UserClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
                return StringUtils.isNotBlank(secretKey);
            } else {
                throw new TOTPException(
                        "Cannot find the user realm for the given tenant domain : " +
                                CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPAccessController failed while trying to access userRealm of the user : " +
                            tenantAwareUsername, e);
        }
    }

    /**
     * Verify whether a given token is valid for a stored local user.
     *
     * @param token    TOTP Token which needs to be validated
     * @param context  Authentication context
     * @param username Username of the user
     * @return true if token is valid otherwise false
     * @throws TOTPException UserRealm for user or tenant domain is null
     */
    private boolean isValidTokenLocalUser(int token, String username, AuthenticationContext context)
            throws TOTPException {

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = null;
        try {
            TOTPAuthenticatorCredentials totpAuthenticator = getTotpAuthenticator(context, tenantDomain);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm
                        .getUserStoreManager().getUserClaimValues
                                (tenantAwareUsername, new String[]
                                        {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                String secretKey = TOTPUtil.decrypt(
                        userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL));
                return totpAuthenticator.authorize(secretKey, token);
            } else {
                throw new TOTPException(
                        "Cannot find the user realm for the given tenant domain : " +
                                CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPTokenVerifier failed while trying to access userRealm of the user : " +
                            tenantAwareUsername, e);
        } catch (CryptoException e) {
            throw new TOTPException("Error while decrypting the key", e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException(
                    "TOTPTokenVerifier cannot find the property value for encodingMethod");
        }
    }

    /**
     * Verify whether a given token is valid for the federated user.
     *
     * @param token        TOTP Token which needs to be validated
     * @param userId       Federated user id.
     * @param tenantDomain Tenant domain.
     * @param context      Authentication context
     * @return true if token is valid otherwise false
     * @throws TOTPException UserRealm for user or tenant domain is null
     */
    private boolean isValidTokenFederatedUser(int token, String userId, String tenantDomain,
                                              AuthenticationContext context) throws TOTPException {

        try {
            TOTPAuthenticatorCredentials totpAuthenticator = getTotpAuthenticator(context, tenantDomain);
            TOTPSecretKeyDAO totpSecretKeyDAO = DAOFactory.getInstance().getTOTPSecretKeyDAO();
            String secretKey = TOTPUtil.decrypt(totpSecretKeyDAO.getTOTPSecretKeyOfFederatedUser(userId));
            return totpAuthenticator.authorize(secretKey, token);
        } catch (CryptoException e) {
            throw new TOTPException("Error while decrypting the key", e);
        }
    }

    /**
     * Execute account lock flow for TOTP verification failures.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void handleTotpVerificationFail(AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER);
		/*
		Account locking is not done for federated flows.
		Check whether account locking enabled for TOTP to keep backward compatibility.
		No need to continue if the account is already locked.
		 */
        if (!TOTPUtil.isLocalUser(context) || !TOTPUtil.isAccountLockingEnabledForTotp() ||
                TOTPUtil.isAccountLocked(authenticatedUser.getUserName(), authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserStoreDomain())) {
            return;
        }
        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = TOTPUtil.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return;
                    }
                case TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_TIME:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case TOTPAuthenticatorConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }
        String username = context.getProperty("username").toString();
        Map<String, String> claimValues = getUserClaimValues(authenticatedUser, username);
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = 0;
        if (NumberUtils.isNumber(claimValues.get(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM))) {
            currentAttempts = Integer.parseInt(claimValues.get(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM));
        }
        int failedLoginLockoutCountValue = 0;
        if (NumberUtils.isNumber(claimValues.get(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            failedLoginLockoutCountValue =
                    Integer.parseInt(claimValues.get(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            // Calculate the incremental unlock-time-interval in milli seconds.
            unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                    failedLoginLockoutCountValue));
            // Calculate unlock-time by adding current-time and unlock-time-interval in milli seconds.
            long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
            updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            updatedClaims.put(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            IdentityUtil.threadLocalProperties.get().put(TOTPAuthenticatorConstants.ADMIN_INITIATED, false);
            setUserClaimValues(authenticatedUser, username, updatedClaims);
            String errorMessage = String.format("User account: %s is locked.", authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage);
        } else {
            updatedClaims
                    .put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(authenticatedUser, username, updatedClaims);
        }
    }

    private TOTPAuthenticatorCredentials getTotpAuthenticator(AuthenticationContext context, String tenantDomain) {

        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
        if (TOTPAuthenticatorConstants.BASE64
                .equals(TOTPUtil.getEncodingMethod(tenantDomain, context))) {
            encoding = TOTPKeyRepresentation.BASE64;
        }
        long timeStep = TimeUnit.SECONDS.toMillis(TOTPUtil.getTimeStepSize(context));
        int windowSize = TOTPUtil.getWindowSize(context);
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder totpAuthenticatorConfigBuilder =
                new TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder()
                        .setKeyRepresentation(encoding).setWindowSize(windowSize)
                        .setTimeStepSizeInMillis(timeStep);
        TOTPAuthenticatorCredentials totpAuthenticator =
                new TOTPAuthenticatorCredentials(totpAuthenticatorConfigBuilder.build());
        return totpAuthenticator;
    }

    private boolean isFederatedUser(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.isFederatedUser();
    }

    private void resetTotpFailedAttempts(AuthenticationContext context) throws AuthenticationFailedException {

		/*
		Check whether account locking enabled for TOTP to keep backward compatibility.
		Account locking is not done for federated flows.
		 */
        if (!TOTPUtil.isLocalUser(context) || !TOTPUtil.isAccountLockingEnabledForTotp()) {
            return;
        }
        AuthenticatedUser authenticatedUser =
                (AuthenticatedUser) context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER);
        Property[] connectorConfigs = TOTPUtil.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());

        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        String username = context.getProperty("username").toString();
        String usernameWithDomain = IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain());
        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            // Avoid updating the claims if they are already zero.
            String[] claimsToCheck = {TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM,
                    TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(usernameWithDomain, claimsToCheck,
                    UserCoreConstants.DEFAULT_PROFILE);
            String failedTotpAttempts = userClaims.get(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM);
            String failedLoginLockoutCount =
                    userClaims.get(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM);

            if (NumberUtils.isNumber(failedTotpAttempts) && Integer.parseInt(failedTotpAttempts) > 0 ||
                    NumberUtils.isNumber(failedLoginLockoutCount) && Integer.parseInt(failedLoginLockoutCount) > 0) {
                Map<String, String> updatedClaims = new HashMap<>();
                updatedClaims.put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, "0");
                updatedClaims.put(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                userStoreManager
                        .setUserClaimValues(usernameWithDomain, updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while resetting failed TOTP attempts count for user: " + username, e);
            }
            String errorMessage = "Failed to reset failed attempts count for user : " + username;
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser, String username)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                    authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), new String[]{
                            TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM,
                            TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM},
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while reading user claims of user: " + authenticatedUser.getUserName(), e);
            }
            String errorMessage = "Failed to read user claims for user : " + authenticatedUser.getUserName();
            throw new AuthenticationFailedException(errorMessage, e);
        }
        return claimValues;
    }

    private void setUserClaimValues(AuthenticatedUser authenticatedUser, String username,
                                    Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while updating user claims of user: " + authenticatedUser.getUserName(), e);
            }
            String errorMessage = "Failed to update user claims for user : " + authenticatedUser.getUserName();
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private String getUserId(AuthenticatedUser authenticatedUser, AuthenticationContext context,
                             StepConfig stepConfig, String tenantDomain) throws TOTPException {

        String userId;
        String username = authenticatedUser.getUserName();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        String idpName = stepConfig.getAuthenticatedIdP();
        int tenantId = getTenantID(tenantDomain);
        int appTenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());

        try {
            int idpId = UserSessionStore.getInstance().getIdPId(idpName, appTenantId);
            userId = UserSessionStore.getInstance().
                    getUserId(username, tenantId, userStoreDomain, idpId);
            if (userId == null) {
                userId = UUID.randomUUID().toString();
                UserSessionStore.getInstance().storeUserData(userId, username, tenantId,
                            userStoreDomain, idpId);
            }
        } catch (UserSessionException e) {
            throw new TOTPException("Error while storing session data for user: " + username + " of " +
                    "user store domain: " + userStoreDomain + " in tenant domain: " + tenantDomain, e);
        }
        return userId;
    }

    private int getTenantID(String tenantDomain) {

        return (tenantDomain == null) ? MultitenantConstants.INVALID_TENANT_ID : IdentityTenantUtil
                .getTenantId(tenantDomain);
    }

    private void storeSecretKeyForFedUsers(AuthenticationContext context) throws TOTPException {

        if (context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP) == null || !Boolean
                .parseBoolean(context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP).toString())) {
            return;
        }
        if (context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL) == null ||
                context.getProperty(TOTPAuthenticatorConstants.FEDERATED_USER_ID) == null) {
            return;
        }
        String secretKey =
                context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL).toString();
        String userId = context.getProperty(TOTPAuthenticatorConstants.FEDERATED_USER_ID).toString();
        DAOFactory.getInstance().getTOTPSecretKeyDAO().setTOTPSecretKeyOfFederatedUser(userId, secretKey);
    }
}
