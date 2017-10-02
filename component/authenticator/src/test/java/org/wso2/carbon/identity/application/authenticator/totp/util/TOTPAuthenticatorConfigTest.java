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
package org.wso2.carbon.identity.application.authenticator.totp.util;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.concurrent.TimeUnit;

import static org.mockito.MockitoAnnotations.initMocks;

public class TOTPAuthenticatorConfigTest {

    private TOTPAuthenticatorConfig totpAuthenticatorConfig;

    @BeforeMethod
    public void setUp() {
        totpAuthenticatorConfig = new TOTPAuthenticatorConfig();
        initMocks(this);
    }

    @Test
    public void testGetKeyModulus() {
        Assert.assertEquals(totpAuthenticatorConfig.getKeyModulus(), (int) Math.pow(10, 6));
    }

    @Test
    public void testGetKeyRepresentation() {
        Assert.assertEquals(totpAuthenticatorConfig.getKeyRepresentation(), TOTPKeyRepresentation.BASE32);
    }

    @Test
    public void testGetTimeWindowFromTime() {
        Assert.assertEquals(totpAuthenticatorConfig.getTimeStepSizeInMillis(), TimeUnit.SECONDS.toMillis(30));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testSetWindowSize() {
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder totpAuthenticatorConfigBuilder = new
                TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder();
        totpAuthenticatorConfigBuilder.setWindowSize(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testSetTimeStepSizeInMillis() {
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder totpAuthenticatorConfigBuilder = new
                TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder();
        totpAuthenticatorConfigBuilder.setTimeStepSizeInMillis(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testSetKeyRepresentation() {
        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder totpAuthenticatorConfigBuilder = new
                TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder();
        totpAuthenticatorConfigBuilder.setKeyRepresentation(null);
    }

}
