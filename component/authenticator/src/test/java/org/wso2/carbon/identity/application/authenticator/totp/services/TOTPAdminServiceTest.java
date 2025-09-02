/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.junit.Assert;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPTokenGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({TOTPUtil.class, TOTPTokenGenerator.class, MultitenantUtils.class, TOTPAuthenticatorCredentials.class
        , IdentityConfigParser.class, CarbonContext.class})
@PowerMockIgnore({"javax.crypto.*"})
public class TOTPAdminServiceTest {

    @Mock
    private UserStoreManager mockUserStoreManager;

    @Mock
    private UserRealm mockUserRealm;

    @BeforeMethod
    public void setUp() {

        repareCarbonHome();

        initMocks(this);
        mockStatic(TOTPUtil.class);
        mockStatic(TOTPTokenGenerator.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityConfigParser.class);
        mockStatic(CarbonContext.class);
    }

    @Test(description = "test ValidateTOTP() method for invalid verification code.")
    public void validateTOTPTest() throws Exception {

        String username = "admin";
        String tenantDomain = "carbon.super";
        String encryptedSecretKey = "encryptedSecretKey";
        String secretKey = "6ZWSWRT4ZOCGH3R2";
        int invalidOTP = 1234;

        when(MultitenantUtils.getTenantDomain(username)).thenReturn(tenantDomain);
        when(MultitenantUtils.getTenantAwareUsername(username)).thenReturn(username + "@" + tenantDomain);
        when(TOTPUtil.getUserRealm(username)).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        Map<String, String> userClaimValues = new HashMap<>();
        userClaimValues.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, encryptedSecretKey);
        doReturn(userClaimValues).when(mockUserStoreManager).getUserClaimValues(username + "@" + tenantDomain,
                new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null);
        when(TOTPUtil.decrypt(anyString())).thenReturn(secretKey);

        IdentityConfigParser identityConfigParser = mock(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        Map<String,Object> configMap = new HashMap<>();
        configMap.put("AdminServices.TOTPAdminService.SelfOperations.Enabled", "false");
        configMap.put("AdminServices.TOTPAdminService.Permission",
                "/permission/admin/manage/identity/usermgt/update");
        when(identityConfigParser.getConfiguration()).thenReturn(configMap);

        mockRealm();

        TOTPAdminService totpAdminService = new TOTPAdminService();
        Assert.assertFalse(totpAdminService.validateTOTP(username, null, invalidOTP));
    }

    private void mockRealm() throws UserStoreException {

        CarbonContext mockCarbonContext = mock(CarbonContext.class);
        when(CarbonContext.getThreadLocalCarbonContext()).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUsername()).thenReturn("admin");
        when(mockCarbonContext.getTenantId()).thenReturn(-1234);
        RealmService realmService = mock(RealmService.class);
        TOTPDataHolder.getInstance().setRealmService(realmService);
        when(realmService.getTenantUserRealm(Matchers.anyInt())).thenReturn(mockUserRealm);
        AuthorizationManager authorizationManager = mock(AuthorizationManager.class);
        when(mockUserRealm.getAuthorizationManager()).thenReturn(authorizationManager);
        when(authorizationManager.isUserAuthorized(anyString(), anyString(), anyString())).thenReturn(true);
    }

    private void repareCarbonHome() {
        System.setProperty(CarbonBaseConstants.CARBON_HOME, this.getClass().getResource("/").getFile());
        System.setProperty("carbon.protocol", "https");
        System.setProperty("carbon.host", "localhost");
        System.setProperty("carbon.management.port", "9443");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
