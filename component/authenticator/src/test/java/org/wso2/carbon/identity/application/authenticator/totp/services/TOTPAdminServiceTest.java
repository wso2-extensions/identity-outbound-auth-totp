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
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPTokenGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({TOTPUtil.class, TOTPTokenGenerator.class, MultitenantUtils.class, TOTPAuthenticatorCredentials.class})
@PowerMockIgnore({"javax.crypto.*"})
public class TOTPAdminServiceTest {

    @Mock
    private UserStoreManager mockUserStoreManager;

    @Mock
    private UserRealm mockUserRealm;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        mockStatic(TOTPUtil.class);
        mockStatic(TOTPTokenGenerator.class);
        mockStatic(MultitenantUtils.class);
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
        when(TOTPUtil.decryptSecret(anyString())).thenReturn(secretKey.getBytes());
        when(TOTPUtil.getWindowSize(tenantDomain)).thenReturn(3);
        when(TOTPUtil.getTimeStepSize(tenantDomain)).thenReturn(30L);

        TOTPAdminService totpAdminService = new TOTPAdminService();
        Assert.assertFalse(totpAdminService.validateTOTP(username, null, invalidOTP));
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
