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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticator;
import org.wso2.carbon.extension.identity.helper.MultiFactorAuthenticationEventListener;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.user.api.UserStoreException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TOTPAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 2009231028659744926L;
    private static Log log = LogFactory.getLog(TOTPAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        String action = request.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN);
        return (token != null || action != null);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (request.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN) != null) {
            if (generateTOTPToken(context)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
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
     * @param request  the request
     * @param response the response
     * @param context  the authentication context
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String username = null;
        AuthenticatedUser authenticatedUser;
        String tenantDomain = context.getTenantDomain();
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (!tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
        }
        TOTPManager totpManager = new TOTPManagerImpl();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace(TOTPAuthenticatorConstants.DEFAULT_LOGIN_ENDPOINT, TOTPAuthenticatorConstants.LOGIN_PAGE);
        String errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace(TOTPAuthenticatorConstants.DEFAULT_LOGIN_ENDPOINT, TOTPAuthenticatorConstants.ERROR_PAGE);
        String retryParam = "";
        try {
            FederatedAuthenticator federatedAuthenticator = new FederatedAuthenticator();
            federatedAuthenticator.getUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty("username"));
            authenticatedUser = (AuthenticatedUser) context.getProperty("authenticatedUser");
            // find the authenticated user.
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException
                        ("Authentication failed!. Cannot proceed further without identifying the user");
            }
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            boolean isTOTPEnabled = totpManager.isTOTPEnabledForLocalUser(username, context);
            if (log.isDebugEnabled()) {
                log.debug("TOTP is enabled by user: " + isTOTPEnabled);
            }
            boolean isTOTPEnabledByAdmin = IdentityHelperUtil.checkSecondStepEnableByAdmin(context);
            if (log.isDebugEnabled()) {
                log.debug("TOTP  is enabled by admin: " + isTOTPEnabledByAdmin);
            }
            if (isTOTPEnabled) {
                String encodedtotpUrl = loginPage + ("?sessionDataKey="
                        + context.getContextIdentifier()) + "&authenticators=" + getName() + "&type=totp"
                        + retryParam + "&username=" + username;
                response.sendRedirect(encodedtotpUrl);
            } else if (isTOTPEnabledByAdmin) {
                String encodedtotpErrorUrl = errorPage + ("?sessionDataKey="
                        + context.getContextIdentifier()) + "&authenticators=" + getName()
                        + "&type=totp_error" + retryParam + "&username=" + username;
                response.sendRedirect(encodedtotpErrorUrl);
            } else {
                //authentication is now completed in this step. update the authenticated user information.
                StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
                if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                    federatedAuthenticator.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.BASIC);
                } else {
                    federatedAuthenticator.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.FEDERETOR);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error when redirecting the totp login response, " +
                    "user : " + username, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException("Error when checking totp enabled for the user : " + username, e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot get the username from first step.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String username = context.getProperty("username").toString();
        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        try {
            MultiFactorAuthenticationEventListener multiFactorAuthenticationEventListener = null;
            if (!context.getTenantDomain().equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
                if (Boolean.parseBoolean((context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION_POLICY_ENABLED))
                        .toString())) {
                    multiFactorAuthenticationEventListener
                            = new MultiFactorAuthenticationEventListener();
                    multiFactorAuthenticationEventListener.doPreApplyCode(username, context);
                }
            } else {
                if (Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap()
                        .get(TOTPAuthenticatorConstants.AUTHENTICATION_POLICY_ENABLED))) {
                    multiFactorAuthenticationEventListener
                            = new MultiFactorAuthenticationEventListener();
                    multiFactorAuthenticationEventListener.doPreApplyCode(username, context);
                }
            }
            TOTPManager totpManager = new TOTPManagerImpl();
            if (token != null) {
                try {
                    int tokenValue = Integer.parseInt(token);
                    if (!totpManager.isValidTokenLocalUser(tokenValue, username, context)) {
                        executeAccountLockingPolicy(context, username, multiFactorAuthenticationEventListener, false);
                        throw new AuthenticationFailedException("Authentication failed, user :  " + username);
                    } else {
                        executeAccountLockingPolicy(context, username, multiFactorAuthenticationEventListener, true);
                        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                    }
                } catch (TOTPException e) {
                    throw new AuthenticationFailedException("TOTP Authentication process failed for user " + username, e);
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Error while checking account locking policies ", e);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("TOTP Authentication process failed for user ", e);
        }
    }


    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getRequestedSessionId();
    }

    @Override
    public String getFriendlyName() {
        return TOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return TOTPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }


    private boolean generateTOTPToken(AuthenticationContext context) throws AuthenticationFailedException {
        String username = context.getProperty("username").toString();
        try {
            TOTPManager totpManager = new TOTPManagerImpl();
            totpManager.generateTOTPTokenLocal(username, context);
            if (log.isDebugEnabled()) {
                log.debug("TOTP Token is generated");
            }
        } catch (TOTPException e) {
            log.error("Error when generating the totp token", e);
            return false;
        }
        return true;
    }

    public void executeAccountLockingPolicy(AuthenticationContext context, String username,
                                            MultiFactorAuthenticationEventListener multiFactorAuthenticationEventListener,
                                            boolean isAuthenticated)
            throws UserStoreException, AuthenticationFailedException {
        if (!context.getTenantDomain().equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
            if ((Boolean.parseBoolean(context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION_POLICY_ENABLED).toString()))
                    && Boolean.parseBoolean(context.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION_LOCKING_POLICY_ENABLED)
                    .toString())) {
                if (multiFactorAuthenticationEventListener != null) {
                    multiFactorAuthenticationEventListener.doPostApplyCode(username, isAuthenticated, context);
                }
            }
        } else {
            if (Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap()
                    .get(TOTPAuthenticatorConstants.AUTHENTICATION_POLICY_ENABLED))
                    && Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap()
                    .get(TOTPAuthenticatorConstants.AUTHENTICATION_LOCKING_POLICY_ENABLED))) {
                if (multiFactorAuthenticationEventListener != null) {
                    multiFactorAuthenticationEventListener.doPostApplyCode(username, isAuthenticated, context);
                }
            }
        }
    }
}