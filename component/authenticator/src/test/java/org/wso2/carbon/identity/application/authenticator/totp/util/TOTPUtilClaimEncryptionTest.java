/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp.util;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;

import java.util.Collections;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Tests how {@link TOTPUtil#getProcessedClaimValue} decides between leaving a claim value for the identity framework
 * to encrypt and encrypting it itself.
 */
public class TOTPUtilClaimEncryptionTest {

    private static final String CLAIM_URI = "http://wso2.org/claims/identity/secretkey";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String PLAIN_VALUE = "PLAINSECRET";

    private MockedStatic<TOTPDataHolder> totpDataHolder;
    private ClaimMetadataManagementService claimService;

    @BeforeMethod
    public void setUp() {

        claimService = mock(ClaimMetadataManagementService.class);
        totpDataHolder = Mockito.mockStatic(TOTPDataHolder.class);
        totpDataHolder.when(TOTPDataHolder::getClaimManagementService).thenReturn(claimService);
    }

    @AfterMethod
    public void tearDown() {

        totpDataHolder.close();
    }

    @Test
    public void testValueLeftPlainWhenClaimHasEnableEncryption() throws Exception {

        LocalClaim localClaim = mock(LocalClaim.class);
        when(localClaim.getClaimURI()).thenReturn(CLAIM_URI);
        when(localClaim.getClaimProperties()).thenReturn(
                Collections.singletonMap(TOTPAuthenticatorConstants.ENABLE_ENCRYPTION, "true"));
        when(claimService.getLocalClaims(TENANT_DOMAIN)).thenReturn(Collections.singletonList(localClaim));

        // The identity framework encrypts this claim, so this component must not.
        assertEquals(TOTPUtil.getProcessedClaimValue(CLAIM_URI, PLAIN_VALUE, TENANT_DOMAIN), PLAIN_VALUE);
    }

    @Test(expectedExceptions = TOTPAuthenticatorException.class)
    public void testFailsWhenClaimMetadataCannotBeRetrieved() throws Exception {

        when(claimService.getLocalClaims(TENANT_DOMAIN)).thenThrow(new ClaimMetadataException("lookup failed"));

        // Guessing "no property" here would encrypt a value the framework may encrypt again.
        TOTPUtil.getProcessedClaimValue(CLAIM_URI, PLAIN_VALUE, TENANT_DOMAIN);
    }

    @Test
    public void testBlankValueIsReturnedAsIsWhenClaimHasNoProperty() throws Exception {

        when(claimService.getLocalClaims(TENANT_DOMAIN)).thenReturn(Collections.emptyList());

        assertEquals(TOTPUtil.getProcessedClaimValue(CLAIM_URI, "", TENANT_DOMAIN), "");
    }
}
