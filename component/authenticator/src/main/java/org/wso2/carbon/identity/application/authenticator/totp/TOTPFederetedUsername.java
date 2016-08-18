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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;


public class TOTPFederetedUsername {
    private static Log log = LogFactory.getLog(TOTPAuthenticator.class);

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    public void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                    AuthenticatedUser authenticatedUser) {
        for (Object o : context.getSequenceConfig().getStepMap().entrySet()) {
            Map.Entry thisEntry = (Map.Entry) o;
            StepConfig stepConfig = (StepConfig) thisEntry.getValue();
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
    public AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (Object o : context.getSequenceConfig().getStepMap().entrySet()) {
            Map.Entry thisEntry = (Map.Entry) o;
            StepConfig stepConfig = (StepConfig) thisEntry.getValue();
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof FederatedApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * Return loggedIn Federated username.
     *
     * @param context the authentication context.
     * @return federated username.
     */
    public String getLoggedInFederatedUser(AuthenticationContext context) {
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
     * Check weather given federated username is in the local user store or not
     *
     * @param federatedUsername federated authenticator's username
     * @return boolean value
     */
    public boolean isExistUserInUserStore(String federatedUsername) throws AuthenticationFailedException,
            UserStoreException {
        UserRealm userRealm;
        boolean isExistUser = false;
        String tenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        try {
            userRealm = realmService.getTenantUserRealm(tenantID);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }
        String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(federatedUsername));
        if (userRealm != null) {
            //Check the federeted username is already exist or not in the user store
            try {
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
    public String getTOTPLocalUsernameAssociatedWithFederatedUser(String federatedUsername,
                                                                  AuthenticationContext context)
            throws TOTPException {
        String localUsername;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql;
        String idpName = context.getProperty("idpName").toString();
        String tenantDomain = context.getTenantDomain();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
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
            throw new TOTPException("Error occurred while getting the associated TOTP Username", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return null;
    }

    /**
     * Get list of secondary user stores
     *
     * @param context the authentication context
     */
    public List<String> listSecondaryUserStores(AuthenticationContext context) {
        List<String> userstores = null;
        String secondaryUserstore;
        secondaryUserstore = TOTPUtil.getSecondaryUserStore(context);
        if (StringUtils.isNotEmpty(secondaryUserstore)) {
            userstores = Arrays.asList(secondaryUserstore.split(","));
        }
        return userstores;
    }

    /**
     * Get username from local
     *
     * @param context           the authentication context.
     * @param federatedUsername federated authenticator's username
     */
    public String getUserNameFromLocal(String federatedUsername, AuthenticationContext context) throws TOTPException {
        String username = null;
        List<String> userStores;
        try {
            userStores = listSecondaryUserStores(context);
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(federatedUsername, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            } else if (isExistUserInUserStore(federatedUsername)) {
                username = federatedUsername;
            }
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw new TOTPException("Cannot find the user in User store", e);
        }
        return username;
    }

    /**
     * Get username from association
     *
     * @param context           the authentication context.
     * @param federatedUsername federated authenticator's username
     */
    public String getUserNameFromAssociation(String federatedUsername, AuthenticationContext context)
            throws TOTPException {
        String tenantAwareLocalUsername;
        String username;
        String tenantAwareFederatedUsername = MultitenantUtils.getTenantAwareUsername(String.valueOf(federatedUsername));
        try {
            //Get associated local username of federated authenticator
            tenantAwareLocalUsername = getTOTPLocalUsernameAssociatedWithFederatedUser(tenantAwareFederatedUsername, context);
            String localUsernameTenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
            username = tenantAwareLocalUsername + TOTPAuthenticatorConstants.TENANT_DOMAIN_COMBINER +
                    localUsernameTenantDomain;
            List<String> userStores;
            userStores = listSecondaryUserStores(context);
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(username, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            }
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw new TOTPException("Error while getting secondary user stores ", e);
        }
        return username;
    }

    /**
     * Get username from federated authenticator's user attribute
     *
     * @param context the authentication context.
     */
    public String getUserNameFromUserAttributes(AuthenticationContext context)
            throws TOTPException {
        Map<ClaimMapping, String> userAttributes;
        String username = null;
        String userAttribute;
        userAttributes = context.getCurrentAuthenticatedIdPs().values().iterator().next().getUser().getUserAttributes();
        Set keySet = userAttributes.keySet();
        userAttribute = TOTPUtil.getUserAttribute(context);
        if (StringUtils.isNotEmpty(userAttribute)) {
//            for (Object akeySet : keySet) {
            Iterator<Map.Entry<ClaimMapping, String>> entries = userAttributes.entrySet().iterator();
            while (entries.hasNext()) {
                Map.Entry<ClaimMapping, String> entry = entries.next();
                String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                String value = entry.getValue();
                if (key.equals(userAttribute)) {
                    String tenantAwareUsername = String.valueOf(value);
                    String usernameTenantDomain = context.getCurrentAuthenticatedIdPs().values().iterator().
                            next().getUser().getTenantDomain();
                    username = tenantAwareUsername + TOTPAuthenticatorConstants.TENANT_DOMAIN_COMBINER +
                            usernameTenantDomain;
                    List<String> userStores;
                    userStores = listSecondaryUserStores(context);
                    if (userStores != null) {
                        for (Object userDomain : userStores) {
                            String federatedUsernameWithDomain;
                            federatedUsernameWithDomain = IdentityUtil.addDomainToName(username,
                                    String.valueOf(userDomain));
                            try {
                                if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                                    username = federatedUsernameWithDomain;
                                    break;
                                }
                            } catch (AuthenticationFailedException | UserStoreException e) {
                                throw new TOTPException("Error while getting secondary user stores ", e);
                            }
                        }
                    }
                    break;
                }
            }
        }
        return username;
    }

    /**
     * Get username from subjectUri of federated authenticator
     *
     * @param context           the authentication context.
     * @param federatedUsername federated authenticator's username
     */
    public String getUserNameFromSbujectURI(String federatedUsername, AuthenticationContext context)
            throws TOTPException {
        List<String> userStores;
        String subjectAttribute = context.getCurrentAuthenticatedIdPs().values().iterator().next().
                getUser().getAuthenticatedSubjectIdentifier();
        String tenantDomain = MultitenantUtils.getTenantDomain(federatedUsername);
        String username = subjectAttribute + TOTPAuthenticatorConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
        userStores = listSecondaryUserStores(context);
        try {
            if (userStores != null) {
                for (Object userDomain : userStores) {
                    String federatedUsernameWithDomain;
                    federatedUsernameWithDomain = IdentityUtil.addDomainToName(username, String.valueOf(userDomain));
                    if (isExistUserInUserStore(federatedUsernameWithDomain)) {
                        username = federatedUsernameWithDomain;
                        break;
                    }
                }
            }
        } catch (AuthenticationFailedException | UserStoreException e) {
            throw new TOTPException("Error while getting secondary user stores ", e);
        }
        return username;
    }
}
