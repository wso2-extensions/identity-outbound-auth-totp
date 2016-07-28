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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


public class TOTPFederetedUsername {
    private static Log log = LogFactory.getLog(TOTPAuthenticator.class);

    /**
     * Check weather given federated username is in the local user store or not
     *
     * @param federatedUsername federated authenticator's username
     * @return boolean value
     */
    public static boolean isExistUserInUserStore(String federatedUsername) throws AuthenticationFailedException {
        UserRealm userRealm;
        boolean isExistUser = false;
        String tenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }
        String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(federatedUsername));
        if (userRealm != null) {
            try {
                //Check the federeted username is already exist or not in the user store
                isExistUser = userRealm.getUserStoreManager().isExistingUser(tenantAwareFederatedUsername);
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Cannot find the user in User store", e);
            }
        }
        return isExistUser;
    }

    /**
     * Get local username which is associated with federated authenticator username
     *
     * @param federatedUsername federated authenticator's username
     * @param context           the authentication context
     * @return local username
     */
    public static String getTOTPLocalUsernameAssociatedWithFederatedUser(String federatedUsername, AuthenticationContext context)
            throws UserProfileException, SQLException {
        String localUsername;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql;
        String idpName = context.getProperty("idpName").toString();
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            sql = "SELECT USER_NAME FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? AND IDP_ID = (SELECT ID " +
                    "FROM IDP WHERE NAME = ? AND TENANT_ID = ?) AND IDP_USER_ID = ?";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpName);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, federatedUsername);
            resultSet = prepStmt.executeQuery();
            connection.commit();
            if (resultSet.next()) {
                localUsername = resultSet.getString(1);
                return localUsername;
            }
        } catch (SQLException e) {
            throw new UserProfileException("Error occurred while getting the associated TOTP Username", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return null;
    }


    public static String getLoggedInFederatedUser(AuthenticationContext context) {
        String username = "";
        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i >= 0; i--) {
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
                String idpName = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedIdP();
                context.setProperty("idpName", idpName);
                username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser().toString();
                if (log.isDebugEnabled()) {
                    log.debug("username :" + username);
                }
                break;
            }
        }
        return username;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    public static void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                           AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
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
    public static AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }
}
