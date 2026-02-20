/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.application.authenticator.totp;

import org.apache.commons.codec.binary.Base64;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class TOTPKeyGeneratorTest {

    @Mock
    UserStoreManager userStoreManager;

    @Mock
    UserRealm userRealm;

    @Mock
    AuthenticationContext authenticationContext;

    private MockedStatic<TOTPUtil> staticTOTPUtil;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        staticTOTPUtil = Mockito.mockStatic(TOTPUtil.class);
    }

    @AfterMethod
    public void tearDown() {
        if (staticTOTPUtil != null) staticTOTPUtil.close();
    }

    @Test
    public void testGenerateClaims() throws UserStoreException, TOTPException, AuthenticationFailedException {
        Map<String, String> claims = new HashMap<>();
        String username = "admin";
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPIssuerDisplayName(anyString(), any())).thenReturn("carbon.super");
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), new String[] {
                TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL }, null)).thenReturn(claims);
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null );
        Assert.assertNotNull(TOTPKeyGenerator.generateClaims(username,false, authenticationContext));
    }

    @Test(expectedExceptions = {TOTPException.class})
    public void testResetLocalWithException() throws AuthenticationFailedException, TOTPException, UserStoreException {
        TOTPKeyGenerator.resetLocal("admin");
    }

    @Test
    public void testAddTOTPClaimsAndRetrievingQRCodeURL() throws AuthenticationFailedException,
            UserStoreException, TOTPException {
        Map<String, String> claims = new HashMap<>();
        String qrCodeUrl = "http://wso2.org/claims/identity/" +
                "qrcodeurl=b3RwYXV0aDovL3RvdHAvY2FyYm9uLnN1cGVyOmFkbWluP3NlY3JldD1udWxsJmlzc3Vlcj1jYXJib24uc3VwZXI=";
        String username = "admin";
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        claims.put(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL, qrCodeUrl);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Assert.assertEquals(TOTPKeyGenerator.addTOTPClaimsAndRetrievingQRCodeURL(claims, username,
                authenticationContext), qrCodeUrl);
    }

    @Test
    public void testResetLocal() throws Exception {
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        Assert.assertTrue(TOTPKeyGenerator.resetLocal("admin"));
    }

    @Test
    public void testGenerateClaimsWithSpecialCharactersInUsername() throws UserStoreException, TOTPException,
            AuthenticationFailedException {
        Map<String, String> claims = new HashMap<>();
        String username = "user#1";
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPIssuerDisplayName(anyString(), any())).thenReturn("carbon.super");
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPDisplayUsername(anyString())).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getTimeStepSize(any(AuthenticationContext.class))).thenReturn(30L);
        staticTOTPUtil.when(() -> TOTPUtil.getProcessedClaimValue(anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(1));
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "");
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), new String[] {
                TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL }, null)).thenReturn(claims);

        Map<String, String> result = TOTPKeyGenerator.generateClaims(username, false, authenticationContext);
        Assert.assertNotNull(result);

        // Verify QR code URL is generated
        String qrCodeUrl = result.get(TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
        Assert.assertNotNull(qrCodeUrl);

        // Decode the Base64 QR code URL
        String decodedQRCodeURL = new String(Base64.decodeBase64(qrCodeUrl));

        // Verify that the username is URL-encoded (# becomes %23)
        Assert.assertTrue(decodedQRCodeURL.contains("user%231"),
                "Username with special characters should be URL-encoded in QR code");
        Assert.assertFalse(decodedQRCodeURL.contains("user#1"),
                "Username with special characters should not appear unencoded in QR code");
    }
}
