/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
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
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.AUTHENTICATOR_TOTP;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.DISPLAY_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.ErrorMessages;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.LOGIN_FAIL_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.LogConstants.ActionIDs.INITIATE_TOTP_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.LogConstants.TOTP_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.TOKEN;
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
    private static final String IS_API_BASED = "IS_API_BASED";
    private static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";
    private static final String LOCKED_REASON = "lockedReason";

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
        boolean canHandle = token != null || action != null || enableTOTP != null;
        if (LoggerUtils.isDiagnosticLogsEnabled() && canHandle) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    TOTP_AUTH_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("TOTP Authenticator handling the authentication.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
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

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    TOTP_AUTH_SERVICE, INITIATE_TOTP_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating TOTP authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String username = null;
        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        boolean showAuthFailureReason = Boolean.parseBoolean(parameterMap.get(
                TOTPAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON));
        boolean showAuthFailureReasonOnLoginPage = false;
        if (showAuthFailureReason) {
            showAuthFailureReasonOnLoginPage = Boolean.parseBoolean(parameterMap.get(
                    TOTPAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE));
        }
        // Auth failure message if account is locked.
        String accLockAuthFailureMsg = parameterMap.get(TOTPAuthenticatorConstants.CONF_ACC_LOCK_AUTH_FAILURE_MSG);
        if (StringUtils.isBlank(accLockAuthFailureMsg)) {
            accLockAuthFailureMsg = LOGIN_FAIL_MESSAGE;
        }

        AuthenticatedUser authenticatedUserFromContext = TOTPUtil.getAuthenticatedUser(context);
        if (authenticatedUserFromContext == null) {
            throw new AuthenticationFailedException(
                    ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode(),
                    ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getMessage());
        }
        String tenantDomain = authenticatedUserFromContext.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            throw new AuthenticationFailedException(
                    ErrorMessages.ERROR_CODE_NO_USER_TENANT.getCode(),
                    ErrorMessages.ERROR_CODE_NO_USER_TENANT.getMessage());
        }
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil
                    .loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
        }

        /*
        The username that the server is using to identify the user, is needed to be identified, as
        for the federated users, the username in the authentication context may not be same as the
        username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

        /*
        If the mappedLocalUsername is blank, that means this is an initial login attempt by a non provisioned
        federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        String loggableUsername = null;
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    TOTP_AUTH_SERVICE, INITIATE_TOTP_REQUEST);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
        }

        try {
            AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(context, authenticatedUserFromContext,
                    mappedLocalUsername, tenantDomain, isInitialFederationAttempt);
            username = UserCoreUtil.addTenantDomainToEntry(authenticatingUser.getUserName(), tenantDomain);
            loggableUsername = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) :
                    username;
            context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER, authenticatingUser);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                Map<String, String> userParams = new HashMap<>();
                userParams.put(LogConstants.InputKeys.USER, loggableUsername);
                Optional<String> optionalUserId = getUserId(authenticatedUserFromContext);
                optionalUserId.ifPresent(userId -> userParams.put(LogConstants.InputKeys.USER_ID, userId));
                diagnosticLogBuilder.inputParams(userParams);
            }
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();

            String errorParam = StringUtils.EMPTY;
            if (showAuthFailureReason) {
                if (errorContext != null && StringUtils.isNotBlank(errorContext.getErrorCode())) {
                    log.debug("Identity error message context is not null.");
                    String errorCode = errorContext.getErrorCode();
                    String reason = null;
                    if (errorCode.contains(":")) {
                        String[] errorCodeWithReason = errorCode.split(":", 2);
                        errorCode = errorCodeWithReason[0];
                        if (errorCodeWithReason.length > 1) {
                            reason = errorCodeWithReason[1];
                        }
                    }
                    // Only adds error code if it is locked error code.
                    if (UserCoreConstants.ErrorCode.USER_IS_LOCKED.equals(errorCode)) {
                        // Change auth failure message if the error code is locked.
                        if (context.isRetrying()) {
                            retryParam = "&authFailure=true&authFailureMsg=" + accLockAuthFailureMsg;
                        }
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(TOTPAuthenticatorConstants.ERROR_CODE, errorCode);
                        if (StringUtils.isNotBlank(reason)) {
                            paramMap.put(TOTPAuthenticatorConstants.LOCKED_REASON, reason);
                        }
                        // Unlocking time in minutes.
                        long unlockTime = getUnlockTimeInMilliSeconds(authenticatingUser);
                        long timeToUnlock = unlockTime - System.currentTimeMillis();
                        if (timeToUnlock > 0) {
                            paramMap.put(TOTPAuthenticatorConstants.UNLOCK_TIME,
                                    String.valueOf(Math.round((double) timeToUnlock / 1000 / 60)));
                        }
                        errorParam = buildErrorParamString(paramMap);
                        Map<String, String> messageContext = getMessageContext(LOCKED_REASON, String.valueOf(reason));
                        String message =
                                String.format("Authentication failed since authenticated user: %s, account is locked.",
                                        getUserStoreAppendedName(username));
                        AuthenticatorMessage authenticatorMessage = getAuthenticatorMessage(message, messageContext);
                        setAuthenticatorMessageToContext(authenticatorMessage, context);
                    }
                }
            }
            boolean isSecretKeyExistForUser = false;
            // Not required to check the TOTP enable state for the initial login of the federated users.
            if (!isInitialFederationAttempt) {
                isSecretKeyExistForUser = isSecretKeyExistForUser(UserCoreUtil.addDomainToName(username,
                        authenticatingUser.getUserStoreDomain()));
            }
            if (isSecretKeyExistForUser) {
                if (log.isDebugEnabled()) {
                    log.debug("Secret key exists for the user: " + username);
                }
            }
            boolean isTOTPEnabledByAdmin = IdentityHelperUtil.checkSecondStepEnableByAdmin(context);
            if (log.isDebugEnabled()) {
                log.debug("TOTP  is enabled by admin: " + isTOTPEnabledByAdmin);
            }
            // This multi option URI is used to navigate back to multi option page to select a different
            // authentication option from TOTP pages.
            String multiOptionURI = getMultiOptionURIQueryParam(request);

            if (isSecretKeyExistForUser &&
                    request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP) == null) {
                //if TOTP is enabled for the user.
                if (!showAuthFailureReasonOnLoginPage) {
                    errorParam = StringUtils.EMPTY;
                }
                String totpLoginPageUrl = buildTOTPLoginPageURL(context, username, retryParam,
                        errorParam, multiOptionURI);
                response.sendRedirect(totpLoginPageUrl);
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Redirecting to TOTP login page.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            } else {
                Map<String, String> runtimeParams = getRuntimeParams(context);

                boolean enrolUserInAuthenticationFlowEnabled = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(
                        context, runtimeParams);
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.inputParam("user enrollment enabled", enrolUserInAuthenticationFlowEnabled);
                }
                if (enrolUserInAuthenticationFlowEnabled &&
                        request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP) == null) {
                    if (context.getProperty(IS_API_BASED) == null) {
                        // If TOTP is not enabled for the user and he hasn't redirected to the enrollment page yet.
                        if (log.isDebugEnabled()) {
                            log.debug("User has not enabled TOTP: " + username);
                        }
                        Map<String, String> claims;
                        if (isInitialFederationAttempt) {
                            claims = TOTPKeyGenerator.generateClaimsForFedUser(username, tenantDomain, context);
                        } else {
                            claims = TOTPKeyGenerator.generateClaims(UserCoreUtil.addDomainToName(username,
                                    authenticatingUser.getUserStoreDomain()), false, context);
                        }
                        Map<String, String> claimProperties = TOTPUtil.getClaimProperties(tenantDomain,
                                TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
                        // Context will have the decrypted secret key all the time.
                        if (claimProperties.containsKey(TOTPAuthenticatorConstants.ENABLE_ENCRYPTION)) {
                            context.setProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                                    claims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL));
                        } else {
                            context.setProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                                    TOTPUtil.decrypt(claims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL)));
                        }
                        context.setProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL,
                                claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL));
                        String qrURL = claims.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
                        TOTPUtil.redirectToEnableTOTPReqPage(request, response, context, qrURL, runtimeParams);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            diagnosticLogBuilder.resultMessage("Redirecting user to the TOTP enable page.");
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                    }
                } else if (Boolean.valueOf(request.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)) ||
                        isTOTPEnabledByAdmin) {
                    //if TOTP is not enabled for the user and user continued the enrollment.
                    context.setProperty(TOTPAuthenticatorConstants.ENABLE_TOTP, true);
                    if (!showAuthFailureReason || isTOTPEnabledByAdmin) {
                        errorParam = StringUtils.EMPTY;
                    }
                    String totpLoginPageUrl = buildTOTPLoginPageURL(context, username, retryParam,
                            errorParam, multiOptionURI);
                    response.sendRedirect(totpLoginPageUrl);
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("Redirecting to TOTP login page.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                } else {
                    //if admin does not enforce TOTP and TOTP is not enabled for the user.
                    context.setSubject(authenticatingUser);
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
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("TOTP is not enabled for the user.");
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    "Error when redirecting the TOTP login response, user : " + loggableUsername, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException(
                    "Error when checking TOTP enabled for the user : " + loggableUsername, e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(
                    "Authentication failed!. Cannot get the username from first step.", e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building TOTP page URL.", e);
        } catch (CryptoException e) {
            throw new AuthenticationFailedException("Error while decrypting the secret key.", e);
        }
    }

    /**
     * Get user account unlock time in milliseconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milliseconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        Map<String, String> claimValues = getUserClaimValues(authenticatedUser,
                new String[]{TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM});
        if (claimValues.get(TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM) == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No value configured for claim: %s, of user: %s",
                        TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, username));
            }
            return 0;
        }
        return Long.parseLong(claimValues.get(TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM));
    }

    private static Map<String, String> getMessageContext(String key, String value) {

        Map <String,String> messageContext = new HashMap<>();
        messageContext.put(key, value);
        return messageContext;
    }

    private String buildTOTPLoginPageURL(AuthenticationContext context, String username, String retryParam,
                                         String errorParam, String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "t=" + context.getLoginTenantDomain() + "&sessionDataKey=" + context.getContextIdentifier()
                + "&authenticators=" + getName() + "&type=totp" + retryParam + "&username=" + username + "&sp="
                + Encode.forUriComponent(context.getServiceProviderName()) + errorParam + multiOptionURI;
        String loginPage = FrameworkUtils.appendQueryParamsStringToUrl(getTOTPLoginPage(context), queryString);
        return buildAbsoluteURL(loginPage);
    }

    private String buildTOTPErrorPageURL(AuthenticationContext context, String username, String retryParam,
                                         String errorParam, String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "t=" + context.getLoginTenantDomain() + "&sessionDataKey=" + context.getContextIdentifier()
                + "&authenticators=" + getName() + "&type=totp_error" + retryParam + "&username=" + username + "&sp="
                + Encode.forUriComponent(context.getServiceProviderName()) + errorParam + multiOptionURI;
        String errorPage = FrameworkUtils.appendQueryParamsStringToUrl(getTOTPErrorPage(context), queryString);
        return buildAbsoluteURL(errorPage);
    }

    private String buildErrorParamString(Map<String, String> paramMap) {

        StringBuilder params = new StringBuilder();
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            params.append("&").append(entry.getKey()).append("=").append(entry.getValue());
        }
        return params.toString();
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

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    TOTP_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing TOTP authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        AuthenticatedUser authenticatingUser =
                (AuthenticatedUser) context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER);
        String username = authenticatingUser.toFullQualifiedUsername();
        String loggableUsername = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) : username;
        validateAccountLockStatusForLocalUser(context, username);

        if (StringUtils.isBlank(token)) {
            handleTotpVerificationFail(context);
            throw new AuthenticationFailedException("Empty TOTP in the request. Authentication Failed for user: " +
                    loggableUsername);
        }
        try {
            int tokenValue = Integer.parseInt(token);
            if (isInitialFederationAttempt(context)) {
                if (!isValidTokenFederatedUser(tokenValue, context)) {
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed for federated user: "
                            + loggableUsername);
                }
            } else {
                checkTotpEnabled(context, username);
                if (!isValidTokenLocalUser(tokenValue, username, context)) {
                    handleTotpVerificationFail(context);
                    throw new AuthenticationFailedException("Invalid Token. Authentication failed, user :  "
                            + loggableUsername);
                }
            }
            if (StringUtils.isNotBlank(username)) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
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
            throw new AuthenticationFailedException("TOTP Authentication process failed for user " + loggableUsername, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException("TOTP Authentication process failed for user " + loggableUsername, e);
        }
        // It reached here means the authentication was successful.
        resetTotpFailedAttempts(context);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    TOTP_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Successfully processed TOTP authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParam(LogConstants.InputKeys.USER, loggableUsername)
                    .inputParams(getApplicationDetails(context));
            Optional<String> optionalUserId = getUserId(context.getSubject());
            optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, userId));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private void checkTotpEnabled(AuthenticationContext context, String username) throws AuthenticationFailedException {

        if (context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP) != null && Boolean
                .valueOf(context.getProperty(TOTPAuthenticatorConstants.ENABLE_TOTP).toString())) {
            try {
                checkForUpdatedSecretKey(context, username);
                //adds the claims to the profile if the user enrol and continued.
                Map<String, String> claims = new HashMap<>();
                if (context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL) != null &&
                        !isSecretKeyExistForUser(username)) {
                    String secretKey = context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL).toString();
                    String tenantDomain = context.getTenantDomain();
                    claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.getProcessedClaimValue(
                            TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,secretKey,tenantDomain));
                    // When secret key is available, have to make TOTP_ENABLED_CLAIM_URI true.
                    claims.put(TOTPAuthenticatorConstants.TOTP_ENABLED_CLAIM_URI, "true");
                }
                if (context.getProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL) != null) {
                    claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL,
                            context.getProperty(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL).toString());
                }
                TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username, context);
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("Error while adding TOTP claims to the user : " +
                        (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) : username), e);
            }
        }
    }

    /**
     * Update the secret key in the context with value in database before validate.
     *
     * @param context  Authenticated context.
     * @param username Authenticated users' username.
     * @throws AuthenticationFailedException When getting the secret key from database.
     */
    private void checkForUpdatedSecretKey(AuthenticationContext context, String username)
            throws AuthenticationFailedException {

        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername,
                                new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                String secretKey = userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
                // Context will have the decrypted secret key all the time.
                if (StringUtils.isNotEmpty(secretKey)) {
                    context.setProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.decrypt(secretKey));
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while getting TOTP secret key of the user: " +
                    (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) : username), e);
        } catch (CryptoException e) {
            throw new AuthenticationFailedException("Error while decrypting the secret key for user : " +
                    (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(username) : username), e);
        }
    }

    private void validateAccountLockStatusForLocalUser(AuthenticationContext context, String username)
            throws AuthenticationFailedException {

        boolean isLocalUser = TOTPUtil.isLocalUser(context);
        AuthenticatedUser authenticatedUserObject =
                (AuthenticatedUser) context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        if (isLocalUser &&
                TOTPUtil.isAccountLocked(authenticatedUserObject.getUserName(), tenantDomain, userStoreDomain)) {
            String errorMessage =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            getUserStoreAppendedName(username));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            String accountLockedReason = StringUtils.EMPTY;
            try {
                UserRealm userRealm = TOTPUtil.getUserRealm(username);
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                        IdentityUtil.addDomainToName(authenticatedUserObject.getUserName(),
                                authenticatedUserObject.getUserStoreDomain()),
                        new String[]{TOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI},
                        UserCoreConstants.DEFAULT_PROFILE);
                if (claimValues != null) {
                    accountLockedReason = claimValues.get(TOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI);
                }
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException(errorMessage + " Could not get the account locked reason.");
            }
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                    UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":" + accountLockedReason);
            String message =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            getUserStoreAppendedName(username));
            AuthenticatorMessage authenticatorMessage = getAuthenticatorMessage
                    (message, null);
            setAuthenticatorMessageToContext(authenticatorMessage, context);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            throw new AuthenticationFailedException(errorMessage);
        }
    }

    private static void setAuthenticatorMessageToContext(AuthenticatorMessage errorMessage,
                                                         AuthenticationContext context) {

        context.setProperty(AUTHENTICATOR_MESSAGE, errorMessage);
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
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata tokenMetadata = new AuthenticatorParamMetadata(
                TOKEN, DISPLAY_TOKEN, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, TOTPAuthenticatorConstants.TOTP_AUTHENTICATOR);
        authenticatorParamMetadataList.add(tokenMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(TOKEN);
        authenticatorData.setRequiredParams(requiredParams);

        return Optional.of(authenticatorData);
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Generate TOTP token.
     *
     * @param context AuthenticationContext
     * @return true, if token is generated successfully
     */
    private boolean generateOTPAndSendByEmail(AuthenticationContext context) {

        String username = TOTPUtil.getAuthenticatedUser(context).getAuthenticatedSubjectIdentifier();

        if (!TOTPUtil.isSendVerificationCodeByEmailEnabled()) {
            String appName = context.getServiceProviderName();
            String tenantDomain = context.getTenantDomain();
            String sessionDataKey = context.getContextIdentifier();

            String msg = "Sending verification code by email is disabled by admin. An attempt was made to send a " +
                    "verification code by email for user: %s for application: %s of %s tenant using sessionDataKey: %s";
            log.warn(String.format(msg, username, appName, tenantDomain, sessionDataKey));
            return false;
        }

        if (StringUtils.isBlank(username)) {
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
    private boolean isSecretKeyExistForUser(String username)
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
                            (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(tenantAwareUsername) :
                                    tenantAwareUsername), e);
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
                Map<String, String> userClaimValues;

                // Confirm if TOTP reuse is disabled and if required claims are present.
                if (TOTPUtil.isPreventTOTPCodeReuseEnabled() && TOTPUtil.doesUsedTimeWindowsClaimExist(tenantDomain)) {
                    userClaimValues = userRealm
                            .getUserStoreManager().getUserClaimValues
                                    (tenantAwareUsername, new String[] {
                                            TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                                            TOTPAuthenticatorConstants.USED_TIME_WINDOWS
                                    }, null);
                } else {
                    userClaimValues = userRealm
                            .getUserStoreManager().getUserClaimValues
                                    (tenantAwareUsername, new String[]
                                            {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
                }
                String secretKeyClaimValue = userClaimValues.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
                if (secretKeyClaimValue == null) {
                    throw new TOTPException("Secret key claim is null for the user : " +
                            (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(tenantAwareUsername) :
                                    tenantAwareUsername));
                }
                String secretKey = TOTPUtil.decrypt(secretKeyClaimValue);
                return totpAuthenticator.authorize(secretKey, token, context,
                        userClaimValues.get(TOTPAuthenticatorConstants.USED_TIME_WINDOWS), tenantDomain, null);
            } else {
                throw new TOTPException(
                        "Cannot find the user realm for the given tenant domain : " +
                                CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException(
                    "TOTPTokenVerifier failed while trying to access userRealm of the user : " +
                            (LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(tenantAwareUsername) :
                                    tenantAwareUsername), e);
        } catch (CryptoException e) {
            throw new TOTPException("Error while decrypting the key", e);
        } catch (AuthenticationFailedException e) {
            throw new TOTPException(
                    "TOTPTokenVerifier cannot find the property value for encodingMethod");
        } catch (ClaimMetadataException e) {
            throw new TOTPException("Error while obtaining used tokens", e);
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

    /**
     * Verify whether a given token is valid for the federated user.
     *
     * @param token   TOTP Token which needs to be validated
     * @param context Authentication context
     * @return true if token is valid otherwise false
     * @throws TOTPException If an error occurred while validating token
     */
    private boolean isValidTokenFederatedUser(int token, AuthenticationContext context)
            throws TOTPException {

        String secretKey = null;
        if (context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL) != null) {
            secretKey = context.getProperty(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL).toString();
        }
        TOTPAuthenticatorCredentials totpAuthenticator = getTotpAuthenticator(context, context.getTenantDomain());
        return totpAuthenticator.authorize(secretKey, token, context, null, null, null);
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
        boolean accountLockOnFailedAttemptsEnabled = false;
        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = TOTPUtil.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                case TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_ENABLE:
                    accountLockOnFailedAttemptsEnabled = Boolean.parseBoolean(connectorConfig.getValue());
                    break;
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

        if (!accountLockOnFailedAttemptsEnabled) {
            return;
        }

        Map<String, String> claimValues = getUserClaimValues(authenticatedUser, new String[]{
                TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM,
                TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM});
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
            if (unlockTimePropertyValue != 0) {
                // Calculate the incremental unlock-time-interval in milli seconds.
                unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                        failedLoginLockoutCountValue));
                // Calculate unlock-time by adding current-time and unlock-time-interval in milli seconds.
                long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
                updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            }
            updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(TOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    TOTPAuthenticatorConstants.MAX_TOTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.threadLocalProperties.get().put(TOTPAuthenticatorConstants.ADMIN_INITIATED, false);
            setUserClaimValues(authenticatedUser, updatedClaims);
            String errorMessage = String.format("User account: %s is locked.", (LoggerUtils.isLogMaskingEnable ?
                    LoggerUtils.getMaskedContent(authenticatedUser.getUserName()) : authenticatedUser.getUserName()));
            AuthenticatorMessage authenticatorMessage = getAuthenticatorMessage(errorMessage, null);
            setAuthenticatorMessageToContext(authenticatorMessage, context);
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                    UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":" +
                            TOTPAuthenticatorConstants.MAX_TOTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            throw new AuthenticationFailedException(errorMessage);
        } else {
            updatedClaims
                    .put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(authenticatedUser, updatedClaims);
        }
    }

    private static AuthenticatorMessage getAuthenticatorMessage(String errorMessage, Map<String, String> context) {

        return new AuthenticatorMessage(FrameworkConstants.AuthenticatorMessageType.ERROR,
                UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                errorMessage,
                context);
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
                    !Boolean.parseBoolean(connectorConfig.getValue()) ||
                    (TOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_ENABLE
                            .equals(connectorConfig.getName())) && !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        String username = authenticatedUser.toFullQualifiedUsername();
        String usernameWithDomain = IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                authenticatedUser.getUserStoreDomain());
        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            // Avoid updating the claims if they are already zero.
            String[] claimsToCheck = {TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(usernameWithDomain, claimsToCheck,
                    UserCoreConstants.DEFAULT_PROFILE);
            String failedTotpAttempts = userClaims.get(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM);

            Map<String, String> updatedClaims = new HashMap<>();
            updatedClaims.put(TOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());

            if (NumberUtils.isNumber(failedTotpAttempts) && Integer.parseInt(failedTotpAttempts) > 0) {
                updatedClaims.put(TOTPAuthenticatorConstants.TOTP_FAILED_ATTEMPTS_CLAIM, "0");
            }
            userStoreManager
                    .setUserClaimValues(usernameWithDomain, updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while resetting failed TOTP attempts count for user: " + username, e);
            }
            String errorMessage = "Failed to reset failed attempts count for user : " + (LoggerUtils.isLogMaskingEnable
                    ? LoggerUtils.getMaskedContent(username) : username);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser, String[] claims)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            String username = authenticatedUser.toFullQualifiedUsername();
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                            authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), claims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while reading user claims of user: " + authenticatedUser.getUserName(), e);
            }
            String errorMessage = "Failed to read user claims for user : " + (LoggerUtils.isLogMaskingEnable ?
                    LoggerUtils.getMaskedContent(authenticatedUser.getUserName()) : authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage, e);
        }
        return claimValues;
    }

    private void setUserClaimValues(AuthenticatedUser authenticatedUser, Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            String username = authenticatedUser.toFullQualifiedUsername();
            UserRealm userRealm = TOTPUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while updating user claims of user: " + authenticatedUser.getUserName(), e);
            }
            String errorMessage = "Failed to update user claims for user : " + (LoggerUtils.isLogMaskingEnable ?
                    LoggerUtils.getMaskedContent(authenticatedUser.getUserName()) : authenticatedUser.getUserName());
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private boolean isJitProvisioningEnabled(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return false;
        }
        return provisioningConfig.isProvisioningEnabled();
    }

    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting userstore: %s as the provisioning userstore for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = TOTPDataHolder.getInstance().getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format(
                                ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(String.format(
                    ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
        }
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }

        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw new AuthenticationFailedException(
                    ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode(),
                    ErrorMessages.ERROR_CODE_NO_FEDERATED_USER.getMessage());
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param context                    Authentication context
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticationContext context,
                                                        AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }

        if (!isJitProvisioningEnabled(authenticatedUserInContext, tenantDomain)) {
            throw new AuthenticationFailedException(
                    ErrorMessages.ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION.getCode(),
                    ErrorMessages.ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION.getMessage());
        }

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            context.setProperty(TOTPAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT, true);
            return authenticatedUserInContext;
        }

        /*
        At this point, the authenticating user is in our system but can have a different mapped username compared to the
        identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
        with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    private boolean isInitialFederationAttempt(AuthenticationContext context) {

        if (context.getProperty(TOTPAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT) != null) {
            return Boolean.parseBoolean(context.
                    getProperty(TOTPAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT).toString());
        }
        return false;
    }

    /**
     * Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * Get the user id from the authenticated user.
     *
     * @param authenticatedUser AuthenticationContext.
     * @return User id.
     */
    private Optional<String> getUserId(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null) {
            return Optional.empty();
        }
        try {
            if (authenticatedUser.getUserId() != null) {
                return Optional.ofNullable(authenticatedUser.getUserId());
            }
        } catch (UserIdNotFoundException e) {
            log.debug("Error while getting the user id from the authenticated user.", e);
        }
        return Optional.empty();
    }

    /**
     * Set i18n key.
     *
     * @return the i18n key
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_TOTP;
    }
}
