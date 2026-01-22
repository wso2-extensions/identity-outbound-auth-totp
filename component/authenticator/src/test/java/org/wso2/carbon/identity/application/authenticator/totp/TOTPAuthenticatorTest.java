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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.DISPLAY_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.TOKEN;

public class TOTPAuthenticatorTest {

    private static final String USER_STORE_DOMAIN = "PRIMARY";

    // Static mocks
    private MockedStatic<TOTPUtil> staticTOTPUtil;
    private MockedStatic<ConfigurationFacade> staticConfigurationFacade;
    private MockedStatic<TOTPTokenGenerator> staticTOTPTokenGenerator;
    private MockedStatic<FileBasedConfigurationBuilder> staticFileBasedConfigurationBuilder;
    private MockedStatic<IdentityHelperUtil> staticIdentityHelperUtil;
    private MockedStatic<FederatedAuthenticatorUtil> staticFederatedAuthenticatorUtil;
    private MockedStatic<IdentityUtil> staticIdentityUtil;
    private MockedStatic<IdentityTenantUtil> staticIdentityTenantUtil;
    private MockedStatic<LoggerUtils> staticLoggerUtils;
    private MockedStatic<ServiceURLBuilder> staticServiceURLBuilder;
    // Add static mock for TOTPDataHolder
    private MockedStatic<TOTPDataHolder> staticTOTPDataHolder;

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
    private TOTPDataHolder totpDataHolder;

    @Mock
    private IdpManager idpManager;

    @Mock
    private IdentityProvider identityProvider;

    @Mock
    private JustInTimeProvisioningConfig justInTimeProvisioningConfig;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

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

    @Spy
    private Map<String,String> mockedRuntimeParams;

    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @Mock
    ExternalIdPConfig externalIdPConfig;

    @BeforeMethod
    public void setUp() {

        totpAuthenticator = new TOTPAuthenticator();
        MockitoAnnotations.openMocks(this);

        staticTOTPUtil = Mockito.mockStatic(TOTPUtil.class);
        staticConfigurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
        staticTOTPTokenGenerator = Mockito.mockStatic(TOTPTokenGenerator.class);
        staticFileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
        staticIdentityHelperUtil = Mockito.mockStatic(IdentityHelperUtil.class);
        staticFederatedAuthenticatorUtil = Mockito.mockStatic(FederatedAuthenticatorUtil.class);
        staticIdentityUtil = Mockito.mockStatic(IdentityUtil.class);
        staticIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        staticLoggerUtils = Mockito.mockStatic(LoggerUtils.class);
        staticServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class);
        // Initialize static mock for TOTPDataHolder
        staticTOTPDataHolder = Mockito.mockStatic(TOTPDataHolder.class);

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        staticIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)).thenReturn(1);
        staticLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {
        if (staticServiceURLBuilder != null) staticServiceURLBuilder.close();
        if (staticLoggerUtils != null) staticLoggerUtils.close();
        if (staticIdentityTenantUtil != null) staticIdentityTenantUtil.close();
        if (staticIdentityUtil != null) staticIdentityUtil.close();
        if (staticFederatedAuthenticatorUtil != null) staticFederatedAuthenticatorUtil.close();
        if (staticIdentityHelperUtil != null) staticIdentityHelperUtil.close();
        if (staticFileBasedConfigurationBuilder != null) staticFileBasedConfigurationBuilder.close();
        if (staticTOTPTokenGenerator != null) staticTOTPTokenGenerator.close();
        if (staticConfigurationFacade != null) staticConfigurationFacade.close();
        if (staticTOTPUtil != null) staticTOTPUtil.close();
        // Close static mock for TOTPDataHolder
        if (staticTOTPDataHolder != null) staticTOTPDataHolder.close();
    }

    private void mockServiceURLBuilder() throws URLBuilderException {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() throws URLBuilderException {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        staticServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    // Utility to invoke private methods via reflection (replaces PowerMock Whitebox)
    private static Object invokePrivate(Object target, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method m = target.getClass().getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return m.invoke(target, args);
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
    public void testGetContextIdentifier() {

        when(httpServletRequest.getRequestedSessionId()).thenReturn("234567890");
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn("234567890");
        Assert.assertEquals(totpAuthenticator.getContextIdentifier(httpServletRequest), "234567890");

        when(httpServletRequest.getRequestedSessionId()).thenReturn("234567890");
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(null);
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

        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();

        Assert.assertEquals(TOTPUtil.getTOTPLoginPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getLoginPage() test for get the loginPage url from constant file.")
    public void testGetLoginPageFromConstantFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();
        Assert.assertEquals(TOTPUtil.getTOTPLoginPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromXMLFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();
        Assert.assertEquals(TOTPUtil.getTOTPErrorPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromConstantFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();

        Assert.assertEquals(TOTPUtil.getTOTPErrorPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "Test case for generateTOTPToken() method success.")
    public void testGenerateTOTPToken() throws Exception {

        String username = "admin";
        staticTOTPTokenGenerator.when(() -> TOTPTokenGenerator.generateTOTPTokenLocal(eq(username), any(AuthenticationContext.class))).thenReturn("123456");

        staticTOTPUtil.when(TOTPUtil::isSendVerificationCodeByEmailEnabled).thenReturn(true);

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty("username", username);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
        Object result = invokePrivate(totpAuthenticator, "generateOTPAndSendByEmail",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext);
        Assert.assertTrue((Boolean) result);
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

        staticTOTPUtil.when(TOTPUtil::isSendVerificationCodeByEmailEnabled).thenReturn(true);
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        staticTOTPTokenGenerator.when(() -> TOTPTokenGenerator.generateTOTPTokenLocal(eq(username), eq(authenticationContext))).thenReturn("123456");

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method with generate TOTP token with sending OTP by email disabled.")
    public void testProcessWithSendOTPByEmailDisabled() throws AuthenticationFailedException, LogoutFailedException,
            TOTPException {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        String username = "admin";
        authenticationContext.setProperty("username", username);

        staticTOTPUtil.when(TOTPUtil::isSendVerificationCodeByEmailEnabled).thenReturn(false);

        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        staticTOTPTokenGenerator.when(() -> TOTPTokenGenerator.generateTOTPTokenLocal(eq(username), eq(authenticationContext))).thenReturn("123456");

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.FAIL_COMPLETED);
    }

    @Test(description = "Test case for process() method with send TOTP token failed.")
    public void testProcessWithSendTokenFalse() throws AuthenticationFailedException, LogoutFailedException {

        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(context)).thenReturn(user);
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

        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        String username = "admin";
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null);
        invokePrivate(totpAuthenticator, "isSecretKeyExistForUser", new Class<?>[]{String.class}, "admin");
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when authenticated user is null",
            expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithNullUser() throws AuthenticationFailedException {

        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(context)).thenReturn(null);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method with totp enabled user.")
    public void testInitiateAuthenticationRequest()
            throws AuthenticationFailedException, UserStoreException, URLBuilderException {

        String username = "admin";
        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        // Ensure user id is available for the authenticated user to avoid UserIdNotFoundException
        authenticatedUser.setUserId("dummyUserId");
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty("username", username);
        authenticationContext.setProperty("authenticatedUser", authenticatedUser);
        authenticationContext.setContextIdentifier(UUID.randomUUID().toString());

        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(username, new String[]
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null)).thenReturn(claims);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");
        mockServiceURLBuilder();

        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(authenticatedUser);
        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, authenticationContext);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method federated user who authenticates with " +
            "TOTP for the first time.")
    public void testInitiateAuthenticationRequestForInitialFederatedUserLogin()
            throws AuthenticationFailedException, IdentityProviderManagementException {

        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);

        String username = "admin";
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setUserName(username);
        authenticatedUser.setFederatedIdPName("Google");
        authenticatedUser.setUserId("dummyUserId");
        when(mockedContext.getTenantDomain()).thenReturn(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);

        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(mockedContext)).thenReturn(false);
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(mockedContext)).thenReturn(authenticatedUser);
        staticFederatedAuthenticatorUtil.when(() -> FederatedAuthenticatorUtil.getLoggedInFederatedUser(mockedContext)).
                thenReturn("test@gmail.com@test.com");
        staticFederatedAuthenticatorUtil.when(() -> FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser("test@gmail.com",
                mockedContext)).thenReturn(null);

        // Replace incorrect when(TOTPDataHolder.getInstance()) with static mock
        staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
        when(totpDataHolder.getIdpManager()).thenReturn(idpManager);
        when(idpManager.getIdPByName("Google", TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)).
                thenReturn(identityProvider);
        when(identityProvider.getJustInTimeProvisioningConfig()).thenReturn(justInTimeProvisioningConfig);
        when(justInTimeProvisioningConfig.isProvisioningEnabled()).thenReturn(true);
        staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenReturn(true);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, mockedContext);
        Assert.assertEquals(mockedContext.getProperty(TOTPAuthenticatorConstants.AUTHENTICATED_USER),
                authenticatedUser);
        Assert.assertEquals(mockedContext.getProperty(TOTPAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT),
                true);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin does not enforces TOTP and " +
            "TOTP is not enabled for the user.")
    public void testInitiateAuthenticationRequestWithEnrollment() throws AuthenticationFailedException,
            UserStoreException {

        String username = "admin";
        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        // Ensure user id is available for the authenticated user to avoid UserIdNotFoundException
        authenticatedUser.setUserId("dummyUserId");
        mockedContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        mockedContext.setProperty("username", username);
        mockedContext.setProperty("authenticatedUser", authenticatedUser);
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(mockedContext)).thenReturn(authenticatedUser);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(mockedContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(any())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, mockedContext);
        Assert.assertEquals(mockedContext.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION),
                TOTPAuthenticatorConstants.FEDERETOR);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin enforces TOTP and " +
            "TOTP is not enabled for the user.", priority = 2)
    public void testInitiateAuthenticationRequestAdminEnforces()
            throws AuthenticationFailedException, UserStoreException, IOException, URLBuilderException {

        String username = "admin";
        String multiOptionURL = "https://localhost:9443/samlsso";

        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        // Ensure user id is available for the authenticated user to avoid UserIdNotFoundException
        authenticatedUser.setUserId("dummyUserId");
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        staticTOTPUtil.when(() -> TOTPUtil.getMultiOptionURIQueryParam(any(HttpServletRequest.class))).thenCallRealMethod();
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(httpServletRequest.getParameter("multiOptionURI")).thenReturn(multiOptionURL);
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.ERROR_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(context)).thenReturn(authenticatedUser);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(any())).thenReturn(stepConfig);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        mockServiceURLBuilder();

        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        // Assert everything related to the error scenario.
        Assert.assertTrue(captor.getValue().contains("authenticationendpoint/totp.do"));
        Assert.assertTrue(captor.getValue().contains("sessionDataKey=" + context.getContextIdentifier()));
        Assert.assertTrue(captor.getValue().contains("authenticators=totp"));
        Assert.assertTrue(captor.getValue().contains("type=totp"));
        Assert.assertTrue(captor.getValue().contains("username=" + username));
        Assert.assertTrue(captor.getValue().contains("multiOptionURI=" + URLEncoder.encode(multiOptionURL,
                StandardCharsets.UTF_8.toString())));
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when admin enforces TOTP and " +
            "TOTP is not enabled for the user.", priority = 2)
    public void testInitiateAuthenticationWithEnableTOTP()
            throws AuthenticationFailedException, UserStoreException, IOException {

        String username = "admin";
        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        // Ensure user id is available for the authenticated user to avoid UserIdNotFoundException
        authenticatedUser.setUserId("dummyUserId");
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(context)).thenReturn(authenticatedUser);
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenReturn(true);
        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @DataProvider(name = "isEnrollmentAllowedInRuntimeParams")
    public Object[][] isEnrollmentAllowedInRuntimeParams(){
        return new Object[][]{
                {"true"},
                {"false"},
                {null}
        };
    }

    @Test(dataProvider = "isEnrollmentAllowedInRuntimeParams", description = "Test whether " +
            "isEnrolUserInAuthenticationFlowEnabled() returns true when ENROL_USER_IN_AUTHENTICATIONFLOW is set to " +
            "\"true\" within the runtime parameters")
    public void testIsEnrollmentAllowedInLoginFlowWithRuntimeParams(String isEnrolmentAllowedInRuntimeParams){

        staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenCallRealMethod();
        when(mockedRuntimeParams.get(ENROL_USER_IN_AUTHENTICATIONFLOW)).thenReturn(isEnrolmentAllowedInRuntimeParams);

        if (isEnrolmentAllowedInRuntimeParams != null) {
            Assert.assertEquals(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context, mockedRuntimeParams),
                    Boolean.parseBoolean(isEnrolmentAllowedInRuntimeParams));
        } else {
            Assert.assertFalse(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context, mockedRuntimeParams));
        }
    }


    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = totpAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(mockedContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(mockedContext.getExternalIdP().getIdPName()).thenReturn(TOTPAuthenticatorConstants.LOCAL_AUTHENTICATOR);

        Optional<AuthenticatorData> authenticatorData = totpAuthenticator.getAuthInitiationData(mockedContext);
        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata tokenMetadata = new AuthenticatorParamMetadata(
                TOKEN, DISPLAY_TOKEN, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, TOTPAuthenticatorConstants.TOTP_AUTHENTICATOR);
        authenticatorParamMetadataList.add(tokenMetadata);

        Assert.assertEquals(authenticatorDataObj.getName(), TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        Assert.assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        Assert.assertEquals(authenticatorDataObj.getPromptType(), FrameworkConstants.AuthenticatorPromptType.
                        USER_PROMPT, "Prompt Type should match.");
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);

            Assert.assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            Assert.assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            Assert.assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            Assert.assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter confidential status should match.");
        }
    }

    @Test(description = "Test case for initiateAuthenticationRequest() with INVALID_CREDENTIAL error code showing remaining attempts.")
    public void testInitiateAuthenticationRequestWithInvalidCredentialError() throws Exception {

        String username = "admin";
        mockServiceURLBuilder();
        staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);

        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserId("dummyUserId");
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin@carbon.super");

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty("username", username);
        authenticationContext.setProperty("authenticatedUser", authenticatedUser);
        authenticationContext.setContextIdentifier(UUID.randomUUID().toString());

        // Mock IdentityErrorMsgContext for INVALID_CREDENTIAL error
        org.wso2.carbon.identity.core.model.IdentityErrorMsgContext errorContext =
                mock(org.wso2.carbon.identity.core.model.IdentityErrorMsgContext.class);
        when(errorContext.getErrorCode()).thenReturn(org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.INVALID_CREDENTIAL);
        when(errorContext.getMaximumLoginAttempts()).thenReturn(5);
        when(errorContext.getFailedLoginAttempts()).thenReturn(2);
        staticIdentityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(errorContext);

        // Mock TOTP enabled
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(username, new String[]
                { TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL }, null)).thenReturn(claims);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        staticTOTPUtil.when(() -> TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        staticTOTPUtil.when(() -> TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();
        staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(authenticatedUser);
        staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(TOTPAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON, "true");
        parameterMap.put(TOTPAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE, "true");
        when(authenticatorConfig.getParameterMap()).thenReturn(parameterMap);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, authenticationContext);

        // Verify that redirect was called and the URL contains remaining attempts parameter
        verify(httpServletResponse).sendRedirect(captor.capture());
        String redirectUrl = captor.getValue();

        // Verify that the URL contains the remainingAttempts parameter with value 3 (5 max - 2 failed)
        Assert.assertTrue(redirectUrl.contains("remainingAttempts=3"),
                "Redirect URL should contain remainingAttempts parameter with value 3");
    }

        @Test(description = "Test isEnrolUserInAuthenticationFlowEnabled returns true when runtime param is 'true'")
        public void testIsEnrolUserInAuthFlowEnabledWithRuntimeParamsTrue() {

                Map<String, String> runtimeParams = new HashMap<>();
                runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, "true");

                staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
                                .thenCallRealMethod();
                when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

                boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
                Assert.assertTrue(result);
        }

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled returns false when runtime param is 'false'")
	public void testIsEnrolUserInAuthFlowEnabledWithRuntimeParamsFalse() {

			Map<String, String> runtimeParams = new HashMap<>();
			runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, "false");

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertFalse(result);
	}

	@Test(description = "Test runtime params take precedence over org hierarchy config")
	public void testRuntimeParamsPrecedenceOverOrgConfig() {

			// Runtime params set to false should override any org-level config
			Map<String, String> runtimeParams = new HashMap<>();
			runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, "false");

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			when(mockedContext.getTenantDomain()).thenReturn("wso2.org");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertFalse(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled with empty runtime params falls back to other configs")
	public void testIsEnrolUserInAuthFlowEnabledWithEmptyRuntimeParams() {

			Map<String, String> runtimeParams = new HashMap<>();

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			staticTOTPUtil.when(
							() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(AuthenticationContext.class)))
							.thenReturn(true);

			staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
			when(totpDataHolder.getOrgResourceResolverService()).thenReturn(null);
			when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertTrue(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled with null runtime params falls back")
	public void testIsEnrolUserInAuthFlowEnabledWithNullRuntimeParams() {

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			staticTOTPUtil.when(
							() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(AuthenticationContext.class)))
							.thenReturn(false);

			staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
			when(totpDataHolder.getOrgResourceResolverService()).thenReturn(null);
			when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, null);
			Assert.assertFalse(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled with blank runtime param value falls back")
	public void testIsEnrolUserInAuthFlowEnabledWithBlankRuntimeParamValue() {

			Map<String, String> runtimeParams = new HashMap<>();
			runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, "   ");

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			staticTOTPUtil.when(
							() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(AuthenticationContext.class)))
							.thenReturn(true);

			staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
			when(totpDataHolder.getOrgResourceResolverService()).thenReturn(null);
			when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertTrue(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled with null context and valid runtime params")
	public void testIsEnrolUserInAuthFlowEnabledWithNullContext() {

			Map<String, String> runtimeParams = new HashMap<>();
			runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, "true");

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();

			// Even with null context, runtime params should work
			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(null, runtimeParams);
			Assert.assertTrue(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled when OrgResourceResolverService is null falls back to XML config")
	public void testIsEnrolUserInAuthFlowEnabledWithNullOrgResourceResolverService() {

			Map<String, String> runtimeParams = new HashMap<>();

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			staticTOTPUtil.when(
							() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(AuthenticationContext.class)))
							.thenReturn(false);

			staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
			when(totpDataHolder.getOrgResourceResolverService()).thenReturn(null);
			when(mockedContext.getTenantDomain()).thenReturn("wso2.org");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertFalse(result);
	}

	@Test(description = "Test isEnrolUserInAuthenticationFlowEnabled with blank tenant domain falls back to XML config")
	public void testIsEnrolUserInAuthFlowEnabledWithBlankTenantDomain() {

			Map<String, String> runtimeParams = new HashMap<>();

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			staticTOTPUtil.when(
							() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(AuthenticationContext.class)))
							.thenReturn(true);

			staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(totpDataHolder);
			when(totpDataHolder.getOrgResourceResolverService()).thenReturn(null);
			when(mockedContext.getTenantDomain()).thenReturn("");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertTrue(result);
	}

	@DataProvider(name = "runtimeParamBooleanValuesProvider")
	public Object[][] getRuntimeParamBooleanValues() {

			return new Object[][] {
							{ "true", true },
							{ "false", false },
							{ "TRUE", true },
							{ "FALSE", false },
							{ "True", true },
							{ "False", false }
			};
	}

	@Test(dataProvider = "runtimeParamBooleanValuesProvider", description = "Test isEnrolUserInAuthenticationFlowEnabled with various runtime param boolean values")
	public void testIsEnrolUserInAuthFlowEnabledWithVariousRuntimeParamValues(
					String paramValue, boolean expectedResult) {

			Map<String, String> runtimeParams = new HashMap<>();
			runtimeParams.put(ENROL_USER_IN_AUTHENTICATIONFLOW, paramValue);

			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenCallRealMethod();
			when(mockedContext.getTenantDomain()).thenReturn("carbon.super");

			boolean result = TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(mockedContext, runtimeParams);
			Assert.assertEquals(result, expectedResult);
	}

	@Test(description = "Test progressive enrollment disabled via runtime params skips QR code page")
	public void testProgressiveEnrollmentDisabledViaRuntimeParams()
					throws AuthenticationFailedException, UserStoreException {

			String username = "admin";
			staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
			AuthenticatedUser authenticatedUser = AuthenticatedUser
							.createLocalAuthenticatedUserFromSubjectIdentifier(username);
			authenticatedUser.setFederatedUser(false);
			authenticatedUser.setUserName(username);
			authenticatedUser.setUserId("dummyUserId");
			mockedContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
			mockedContext.setProperty("username", username);
			mockedContext.setProperty("authenticatedUser", authenticatedUser);

			// User does not have TOTP enabled (no secret key)
			Map<String, String> claims = new HashMap<>();
			staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
			staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(mockedContext)).thenReturn(authenticatedUser);
			when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
			when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);

			// Progressive enrollment is disabled via runtime params
			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenReturn(false);
			staticIdentityHelperUtil.when(() -> IdentityHelperUtil.checkSecondStepEnableByAdmin(mockedContext))
							.thenReturn(false);

			when(mockedContext.getSequenceConfig()).thenReturn(sequenceConfig);
			when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
			when(mockedMap.get(any())).thenReturn(stepConfig);
			when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
			when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
			staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
			staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance)
							.thenReturn(fileBasedConfigurationBuilder);
			when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

			totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, mockedContext);

			// Verify that when enrollment is disabled, the user is not redirected to
			// enrollment page
			// and authentication property is set to FEDERETOR (meaning skipped)
			Assert.assertEquals(mockedContext.getProperty(TOTPAuthenticatorConstants.AUTHENTICATION),
							TOTPAuthenticatorConstants.FEDERETOR);
	}

	@Test(description = "Test progressive enrollment enabled via runtime params shows QR code page")
	public void testProgressiveEnrollmentEnabledViaRuntimeParams()
					throws AuthenticationFailedException, UserStoreException, IOException, URLBuilderException {

			String username = "admin";
			mockServiceURLBuilder();
			staticIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(USER_STORE_DOMAIN);
			AuthenticatedUser authenticatedUser = AuthenticatedUser
							.createLocalAuthenticatedUserFromSubjectIdentifier(username);
			authenticatedUser.setFederatedUser(false);
			authenticatedUser.setUserName(username);
			authenticatedUser.setUserId("dummyUserId");
			context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
			context.setLoginTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
			context.setServiceProviderName("test-app");
			context.setContextIdentifier(UUID.randomUUID().toString());
			context.setProperty("username", username);
			context.setProperty("authenticatedUser", authenticatedUser);

			// User does not have TOTP enabled (no secret key)
			Map<String, String> claims = new HashMap<>();
			staticTOTPUtil.when(() -> TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
			staticTOTPUtil.when(() -> TOTPUtil.getAuthenticatedUser(context)).thenReturn(authenticatedUser);
			when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
			when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);

			// Progressive enrollment is enabled via runtime params
			staticTOTPUtil.when(() -> TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any()))
							.thenReturn(true);
			staticTOTPUtil.when(() -> TOTPUtil.getMultiOptionURIQueryParam(any(HttpServletRequest.class)))
							.thenReturn("");
			staticTOTPUtil.when(() -> TOTPUtil.redirectToEnableTOTPReqPage(any(), any(), any(), any(), any()))
							.thenAnswer(invocation -> null);

			staticTOTPUtil.when(() -> TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
			staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance)
							.thenReturn(fileBasedConfigurationBuilder);
			when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
			when(authenticatorConfig.getParameterMap()).thenReturn(new HashMap<>());

			totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);

			// Verify that redirectToEnableTOTPReqPage was called when enrollment is enabled
			staticTOTPUtil.verify(() -> TOTPUtil.redirectToEnableTOTPReqPage(any(), any(), any(), any(), any()));
	}       
}



