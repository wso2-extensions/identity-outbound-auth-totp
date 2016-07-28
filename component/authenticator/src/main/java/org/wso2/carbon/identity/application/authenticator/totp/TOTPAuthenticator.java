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
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

public class TOTPAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static Log log = LogFactory.getLog(TOTPAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        String action = request.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN);
        return (token != null || action != null);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
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
        TOTPManager totpManager = new TOTPManagerImpl();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", TOTPAuthenticatorConstants.LOGIN_PAGE);
        String errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                .replace("authenticationendpoint/login.do", TOTPAuthenticatorConstants.ERROR_PAGE);
        String retryParam = "";
        try {
            getUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty("username"));
            authenticatedUser = (AuthenticatedUser) context.getProperty("authenticatedUser");
            context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
            // find the authenticated user.
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException
                        ("Authentication failed!. Cannot proceed further without identifying the user");
            }
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            boolean isTOTPEnabled = totpManager.isTOTPEnabledForLocalUser(username);
            if (log.isDebugEnabled()) {
                log.debug("TOTP is enabled by user: " + isTOTPEnabled);
            }
            boolean isTOTPEnabledByAdmin = totpManager.isTOTPEnabledByAdmin();
            if (log.isDebugEnabled()) {
                log.debug("TOTP  is enabled by admin: " + isTOTPEnabledByAdmin);
            }
            if (isTOTPEnabled) {
                response.sendRedirect(response.encodeRedirectURL(loginPage +
                        ("?sessionDataKey="
                                + context.getContextIdentifier())) + "&authenticators=" + getName() + "&type=totp"
                        + retryParam + "&username=" + username);
            } else if (isTOTPEnabledByAdmin) {
                response.sendRedirect(response.encodeRedirectURL(errorPage + ("?sessionDataKey="
                        + context.getContextIdentifier())) + "&authenticators=" + getName()
                        + "&type=totp_error" + retryParam + "&username=" + username);
            } else {
                //authentication is now completed in this step. update the authenticated user information.
                StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
                if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                    updateAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.BASIC);
                } else {
                    TOTPFederetedUsername.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
                    context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.FEDERETOR);
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error when redirecting the totp login response, " +
                    "user : " + username, e);
        } catch (TOTPException e) {
            throw new AuthenticationFailedException("Error when checking totp enabled for the user : " + username, e);
        } catch (UserProfileException | SQLException e) {
            throw new AuthenticationFailedException("Error occurred while getting the associated TOTP Username", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String token = request.getParameter(TOTPAuthenticatorConstants.TOKEN);
        String username = context.getProperty("username").toString();
        TOTPManager totpManager = new TOTPManagerImpl();
        if (token != null) {
            try {
                int tokenValue = Integer.parseInt(token);
                if (!totpManager.isValidTokenLocalUser(tokenValue, username)) {
                    throw new AuthenticationFailedException("Authentication failed, user :  " + username);
                }
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
            } catch (TOTPException e) {
                throw new AuthenticationFailedException("TOTP Authentication process failed for user " + username, e);
            }
        }
    }

    /**
     * Check the first step of authenticator type and get username from first step
     *
     * @param context the authentication context
     * @throws AuthenticationFailedException
     */
    private void getUsernameFromFirstStep(AuthenticationContext context) throws AuthenticationFailedException,
            TOTPException, UserProfileException, SQLException {
        String username = null;
        Map<ClaimMapping, String> userAttributes;
        AuthenticatedUser authenticatedUser;
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
            username = getLoggedInLocalUser(context);
            authenticatedUser = getUsername(context);
        } else {
            //Get username from federated authenticator
            String federatedUsername = TOTPFederetedUsername.getLoggedInFederatedUser(context);
            try {
                String usecase = TOTPUtil.getUsecase();
                if (usecase.equals(null) || usecase.equals("") || TOTPAuthenticatorConstants.FIRST_USECASE.equals(usecase)) {
                    if (TOTPFederetedUsername.isExistUserInUserStore(federatedUsername)) {
                        username = federatedUsername;
                    }
                }
                if (TOTPAuthenticatorConstants.SECOND_USECASE.equals(usecase)) {
                    String tenantAwareLocalUsername;
                    String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername
                            (String.valueOf(federatedUsername));
                    //Get associated local username of federated authenticator
                    tenantAwareLocalUsername = TOTPFederetedUsername.getTOTPLocalUsernameAssociatedWithFederatedUser
                            (tenantAwareFederatedUsername, context);
                    String localUsernameTenantDomain = MultitenantUtils.getTenantDomain(tenantAwareLocalUsername);
                    username = tenantAwareLocalUsername + TOTPAuthenticatorConstants.TENANT_DOMAIN_COMBINER +
                            localUsernameTenantDomain;
                }
                if (TOTPAuthenticatorConstants.THIRD_USECASE.equals(usecase)) {
                    userAttributes = context.getCurrentAuthenticatedIdPs().values().iterator().next().getUser()
                            .getUserAttributes();
                    Set keySet = userAttributes.keySet();
                    int size = keySet.size();
                    String userAttribute = TOTPUtil.getUserAttribute();
                    if (!userAttribute.equals(null) && !userAttribute.equals("")) {
                        for (int k = 0; k < size; k++) {
                            String key = String.valueOf(((ClaimMapping) keySet.toArray()[k]).getLocalClaim().getClaimUri());
                            Object value = userAttributes.values().toArray()[k];
                            if (key.equals(userAttribute)) {
                                String tenantAwareUsername = String.valueOf(value);
                                String usernameTenantDomain = context.getCurrentAuthenticatedIdPs().values().iterator()
                                        .next().getUser().getTenantDomain();
                                username = tenantAwareUsername + TOTPAuthenticatorConstants.TENANT_DOMAIN_COMBINER +
                                        usernameTenantDomain;
                                break;
                            }
                        }
                    }
                }
                if (TOTPAuthenticatorConstants.FOUTH_USECASE.equals(usecase)) {
                    username = context.getCurrentAuthenticatedIdPs().values().iterator().next().getUser()
                            .getAuthenticatedSubjectIdentifier();
                }
            } catch (AuthenticationFailedException e) {
                throw new UserProfileException("Error occurred while getting the TOTP authenticator Username", e);
            }
            authenticatedUser = TOTPFederetedUsername.getUsername(context);
        }
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        log.trace("Inside TOTP.getContextIdentifier()");
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

    private String getLoggedInLocalUser(AuthenticationContext context) {
        String username = "";
        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i >= 0; i--) {
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser().toString();
                if (log.isDebugEnabled()) {
                    log.debug("username :" + username);
                }
                break;
            }
        }
        return username;
    }

    private boolean generateTOTPToken(AuthenticationContext context) {
        String username = context.getProperty("username").toString();
        try {
            TOTPManager totpManager = new TOTPManagerImpl();
            totpManager.generateTOTPTokenLocal(username);
            if (log.isDebugEnabled()) {
                log.debug("TOTP Token is generated");
            }
        } catch (TOTPException e) {
            log.error("Error when generating the totp token", e);
            return false;
        }
        return true;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        context.setSubject(authenticatedUser);
    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     */
    private AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }
}