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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

public class TOTPAccessController {

    private static Log log = LogFactory.getLog(TOTPAccessController.class);
    private static volatile TOTPAccessController instance;

    private TOTPAccessController() {
    }

    public static TOTPAccessController getInstance() {
        if (instance == null) {
            synchronized (TOTPAccessController.class) {
                if (instance == null) {
                    instance = new TOTPAccessController();
                }
            }
        }
        return instance;
    }

    public boolean isTOTPEnabledForLocalUser(String username) throws TOTPException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);

            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                String secretKey = userRealm.getUserStoreManager().getUserClaimValue(username,
                        TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, null);
                return StringUtils.isNotBlank(secretKey);
            } else {
                throw new TOTPException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new TOTPException("TOTPAccessController failed while trying to access userRealm of the user : " +
                    username, e);
        }
    }

    /**
     * Get the value whether totp is enabled by admin
     *
     * @return enableTOTP value
     * @throws TOTPException
     */
    public boolean isTOTPEnabledByAdmin(Map<String, String> totpParameters) throws TOTPException {
        return TOTPUtil.checkTOTPEnableByAdmin(totpParameters);
    }
}