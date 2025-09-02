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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({TOTPUtil.class, TOTPTokenGenerator.class, ConfigurationFacade.class, TOTPTokenGenerator.class,
        FileBasedConfigurationBuilder.class, IdentityHelperUtil.class, CarbonContext.class, IdentityUtil.class,
        FederatedAuthenticatorUtil.class})
@PowerMockIgnore({"javax.crypto.*" })
public class TOTPAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";

    @Mock
    private TOTPAuthenticator mockedTOTPAuthenticator;

    @Spy
    private TOTPAuthenticator spy;

    private TOTPAuthenticator totpAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private ConfigurationFacade configurationFacade;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

    @Spy
    private FederatedAuthenticatorUtil federatedAuthenticatorUtil;

    @Mock
    private SequenceConfig sequenceConfig;

    @Mock
    private Map<Integer, StepConfig> mockedMap;

    @Mock
    private StepConfig stepConfig;

    @Mock
    private AuthenticatorConfig authenticatorConfig;

    @Mock
    private ApplicationAuthenticator applicationAuthenticator;

    @Spy
    private AuthenticationContext mockedContext;

    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @BeforeMethod
    public void setUp() {
        totpAuthenticator = new TOTPAuthenticator();
        initMocks(this);
        mockStatic(TOTPUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(TOTPTokenGenerator.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(IdentityHelperUtil.class);
        mockStatic(FederatedAuthenticatorUtil.class);
    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandle() throws Exception {
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.TOKEN)).thenReturn("213432");
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        Assert.assertEquals(totpAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() throws Exception {
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        Assert.assertEquals(totpAuthenticator.canHandle(httpServletRequest), false);
    }

    @Test(description = "Test case for getContextIdentifier() method.")
    public void testGetContextIdentifier(){
        when(httpServletRequest.getRequestedSessionId()).thenReturn("234567890");
        Assert.assertEquals(totpAuthenticator.getContextIdentifier(httpServletRequest), "234567890");

        when(httpServletRequest.getRequestedSessionId()).thenReturn(null);
        Assert.assertNull(totpAuthenticator.getContextIdentifier(httpServletRequest));
    }

    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {
        Assert.assertEquals(totpAuthenticator.getFriendlyName(),
                TOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getName() method.")
    public void testGetName() {
        Assert.assertEquals(totpAuthenticator.getName(), TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() {
        Assert.assertEquals(totpAuthenticator.retryAuthenticationEnabled(), true);
    }

    @Test(description = "TOTPAuthenticator:getLoginPage() test for get the loginPage url from authentication.xml file.")
    public void testGetLoginPageFromXMLFile() throws Exception {
        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        Assert.assertEquals(Whitebox.invokeMethod(totpAuthenticator, "getLoginPage",
                new AuthenticationContext()), TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getLoginPage() test for get the loginPage url from constant file.")
    public void testGetLoginPageFromConstantFile() throws Exception {
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(null);
        Assert.assertEquals(Whitebox.invokeMethod(totpAuthenticator, "getLoginPage",
                new AuthenticationContext()), TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromXMLFile() throws Exception {
        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.ERROR_PAGE);
        Assert.assertEquals(Whitebox.invokeMethod(totpAuthenticator, "getErrorPage",
                new AuthenticationContext()), TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromConstantFile() throws Exception {
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(null);
        Assert.assertEquals(Whitebox.invokeMethod(totpAuthenticator, "getErrorPage",
                new AuthenticationContext()), TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "Test case for generateTOTPToken() method success.")
    public void testGenerateTOTPToken() throws Exception {
        String username = "admin";
        mockStatic(TOTPTokenGenerator.class);
        when(TOTPTokenGenerator.generateTOTPTokenLocal(username, new AuthenticationContext())).thenReturn("123456");
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty("username", username);
        Assert.assertEquals(Whitebox.invokeMethod(totpAuthenticator, "generateTOTPToken",
                authenticationContext), true);
    }

    @Test(description = "Test case for successful logout request.")
    public void testProcessLogoutRequest() throws Exception {
        when(context.isLogoutRequest()).thenReturn(true);
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method with generate TOTP token.")
    public void testProcess() throws AuthenticationFailedException, LogoutFailedException, TOTPException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        String username = "admin";
        authenticationContext.setProperty("username", username);
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        when(TOTPTokenGenerator.generateTOTPTokenLocal(username, authenticationContext)).thenReturn("123456");
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method with send TOTP token failed.")
    public void testProcessWithSendTokenFalse() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.FAIL_COMPLETED);
    }

    @Test(description = "Test case for process() method with totp enabled and incomplete flow.")
    public void testProcessWithEnableTOTP() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn("true");
        doNothing().when(spy).initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);

        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method with totp enabled and successful flow.")
    public void testProcessWithEnableTOTPFalse() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn("true");
        doNothing().when(spy).initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, "other");
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method with send token and successful flow.")
    public void testProcessWithoutTokenComplete() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.TOKEN)).thenReturn(null);
        doNothing().when(spy).initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, "other");
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method when no token is present in the request")
    public void testProcessWithoutToken() throws AuthenticationFailedException, LogoutFailedException {
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.TOKEN)).thenReturn(null);
        doNothing().when(spy).initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        context.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);

        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for isTOTPEnabledForLocalUser with TOTP enabled user ")
    public void testIsTOTPEnabledForLocalUser() throws Exception {
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        String username = "admin";
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null );
        Whitebox.invokeMethod(totpAuthenticator, "isTOTPEnabledForLocalUser", "admin");
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when authenticated user is null",
            expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithNullUser() throws AuthenticationFailedException {
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method with totp enabled user.")
    public void testInitiateAuthenticationRequest() throws AuthenticationFailedException, UserStoreException {

        String username = "admin";
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty("username", username);
        authenticationContext.setProperty("authenticatedUser", authenticatedUser);
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(username, new String[]
                { TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL }, null)).thenReturn(claims);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);

        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, authenticationContext);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin does not enforces TOTP and " +
            "TOTP is not enabled for the user.")
    public void testInitiateAuthenticationRequestWithEnrollment() throws AuthenticationFailedException,
            UserStoreException {

        String username = "admin";
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        mockedContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        mockedContext.setProperty("username", username);
        mockedContext.setProperty("authenticatedUser", authenticatedUser);
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(mockedContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, mockedContext);
        Assert.assertEquals(mockedContext.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION),
                TOTPAuthenticatorConstants.FEDERETOR);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin enforces TOTP and " +
            "TOTP is not enabled for the user.", priority=2)
    public void testInitiateAuthenticationRequestAdminEnforces() throws AuthenticationFailedException, UserStoreException, IOException {

        String username = "admin";
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME));
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin enforces TOTP and " +
            "TOTP is not enabled for the user.", priority=2)
    public void testInitiateAuthenticationWithEnableTOTP() throws AuthenticationFailedException, UserStoreException, IOException {

        String username = "admin";
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context)).thenReturn(true);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

}