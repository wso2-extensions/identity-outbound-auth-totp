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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.DISPLAY_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW;
import static org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants.TOKEN;

@PrepareForTest({TOTPUtil.class, TOTPTokenGenerator.class, ConfigurationFacade.class, TOTPTokenGenerator.class,
        FileBasedConfigurationBuilder.class, IdentityHelperUtil.class, CarbonContext.class,
        FederatedAuthenticatorUtil.class, IdentityUtil.class, ServiceURLBuilder.class, IdentityTenantUtil.class,
        UserSessionStore.class, TOTPDataHolder.class, IdpManager.class, IdentityProvider.class,
        JustInTimeProvisioningConfig.class, LoggerUtils.class})
@PowerMockIgnore({"javax.crypto.*","org.mockito.*","org.powermock.api.mockito.invocation.*"})
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
        initMocks(this);
        mockStatic(TOTPUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(TOTPTokenGenerator.class);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(IdentityHelperUtil.class);
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)).thenReturn(1);
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
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
                PowerMockito.when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                PowerMockito.when(serviceURL.getRelativePublicURL()).thenReturn(path);
                PowerMockito.when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        PowerMockito.when(ServiceURLBuilder.create()).thenReturn(builder);
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

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();

        Assert.assertEquals(TOTPUtil.getTOTPLoginPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getLoginPage() test for get the loginPage url from constant file.")
    public void testGetLoginPageFromConstantFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        when(TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();
        Assert.assertEquals(TOTPUtil.getTOTPLoginPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromXMLFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        when(TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();
        Assert.assertEquals(TOTPUtil.getTOTPErrorPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getErrorPage() test for get the errorPage url from constant file.")
    public void testGetErrorPageFromConstantFile() throws Exception {

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).thenCallRealMethod();
        when(TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();

        Assert.assertEquals(TOTPUtil.getTOTPErrorPage(new AuthenticationContext()),
                TOTPAuthenticatorConstants.ERROR_PAGE);
    }

    @Test(description = "Test case for generateTOTPToken() method success.")
    public void testGenerateTOTPToken() throws Exception {

        String username = "admin";
        mockStatic(TOTPTokenGenerator.class);
        when(TOTPTokenGenerator.generateTOTPTokenLocal(username, new AuthenticationContext())).thenReturn("123456");

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.isSendVerificationCodeByEmailEnabled()).thenReturn(true);

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty("username", username);

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        when(TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
        Assert.assertTrue(Whitebox.invokeMethod(totpAuthenticator, "generateOTPAndSendByEmail",
                authenticationContext));
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

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.isSendVerificationCodeByEmailEnabled()).thenReturn(true);
        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        when(TOTPTokenGenerator.generateTOTPTokenLocal(username, authenticationContext)).thenReturn("123456");

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        when(TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
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

        mockStatic(TOTPUtil.class);
        when(TOTPUtil.isSendVerificationCodeByEmailEnabled()).thenReturn(false);

        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.SEND_TOKEN)).thenReturn("true");
        when(TOTPTokenGenerator.generateTOTPTokenLocal(username, authenticationContext)).thenReturn("123456");

        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        when(TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(user);
        AuthenticatorFlowStatus status = totpAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.FAIL_COMPLETED);
    }

    @Test(description = "Test case for process() method with send TOTP token failed.")
    public void testProcessWithSendTokenFalse() throws AuthenticationFailedException, LogoutFailedException {

        doReturn(true).when(mockedTOTPAuthenticator).canHandle(httpServletRequest);
        mockStatic(TOTPUtil.class);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        when(TOTPUtil.getAuthenticatedUser(context)).thenReturn(user);
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
        userStoreManager.setUserClaimValues(MultitenantUtils.getTenantAwareUsername(username), claims, null);
        Whitebox.invokeMethod(totpAuthenticator, "isSecretKeyExistForUser", "admin");
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method when authenticated user is null",
            expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthenticationRequestWithNullUser() throws AuthenticationFailedException {

        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        when(TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        when(TOTPUtil.getAuthenticatedUser(context)).thenReturn(null);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method with totp enabled user.")
    public void testInitiateAuthenticationRequest()
            throws AuthenticationFailedException, UserStoreException, URLBuilderException {

        String username = "admin";
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty("username", username);
        authenticationContext.setProperty("authenticatedUser", authenticatedUser);
        authenticationContext.setContextIdentifier(UUID.randomUUID().toString());

        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(username, new String[]
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL}, null)).thenReturn(claims);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);

        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("authenticationendpoint/login.do");
        mockServiceURLBuilder();

        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).thenCallRealMethod();
        when(TOTPUtil.getAuthenticatedUser(authenticationContext)).thenReturn(authenticatedUser);
        when(TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        totpAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, authenticationContext);
    }

    @Test(description = "Test case for initiateAuthenticationRequest() method federated user who authenticates with " +
            "TOTP for the first time.")
    public void testInitiateAuthenticationRequestForInitialFederatedUserLogin()
            throws AuthenticationFailedException, IdentityProviderManagementException {

        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(UserSessionStore.class);
        mockStatic(TOTPDataHolder.class);
        mockStatic(IdpManager.class);

        String username = "admin";
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setUserName(username);
        authenticatedUser.setFederatedIdPName("Google");
        authenticatedUser.setUserId("dummyUserId");
        when(mockedContext.getTenantDomain()).thenReturn(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);

        when(TOTPUtil.isLocalUser(mockedContext)).thenReturn(false);
        when(TOTPUtil.getAuthenticatedUser(mockedContext)).thenReturn(authenticatedUser);
        when(FederatedAuthenticatorUtil.getLoggedInFederatedUser(mockedContext)).
                thenReturn("test@gmail.com@test.com");
        when(FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser("test@gmail.com",
                mockedContext)).thenReturn(null);

        when(TOTPDataHolder.getInstance()).thenReturn(totpDataHolder);
        when(totpDataHolder.getIdpManager()).thenReturn(idpManager);
        when(idpManager.getIdPByName("Google", TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)).
                thenReturn(identityProvider);
        when(identityProvider.getJustInTimeProvisioningConfig()).thenReturn(justInTimeProvisioningConfig);
        when(justInTimeProvisioningConfig.isProvisioningEnabled()).thenReturn(true);
        when(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenReturn(true);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
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
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        mockedContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        mockedContext.setProperty("username", username);
        mockedContext.setProperty("authenticatedUser", authenticatedUser);
        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(TOTPUtil.getAuthenticatedUser(mockedContext)).thenReturn(authenticatedUser);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(mockedContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(any())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        when(TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
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

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        context.setContextIdentifier(UUID.randomUUID().toString());

        Map<String, String> claims = new HashMap<>();
        claims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "AnySecretKey");
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(TOTPUtil.getMultiOptionURIQueryParam(any(HttpServletRequest.class))).thenCallRealMethod();
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(httpServletRequest.getParameter("multiOptionURI")).thenReturn(multiOptionURL);
        when(IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.ERROR_PAGE);
        when(TOTPUtil.getTOTPErrorPage(any(AuthenticationContext.class))).thenCallRealMethod();
        when(TOTPUtil.getAuthenticatedUser(context)).thenReturn(authenticatedUser);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(any())).thenReturn(stepConfig);
        when(TOTPUtil.getTOTPLoginPage(any(AuthenticationContext.class))).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        mockServiceURLBuilder();

        when(TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
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
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(USER_STORE_DOMAIN);
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
        authenticatedUser.setFederatedUser(false);
        authenticatedUser.setUserName(username);
        context.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        context.setProperty("username", username);
        context.setProperty("authenticatedUser", authenticatedUser);
        when(TOTPUtil.getAuthenticatedUser(context)).thenReturn(authenticatedUser);
        when(TOTPUtil.getUserRealm(anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(TOTPAuthenticatorConstants.ENABLE_TOTP)).thenReturn(null);
        when(IdentityHelperUtil.checkSecondStepEnableByAdmin(context)).thenReturn(true);
        when(TOTPUtil.getLoginPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.getErrorPageFromXMLFile(any(AuthenticationContext.class), anyString())).
                thenReturn(TOTPAuthenticatorConstants.TOTP_LOGIN_PAGE);
        when(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenReturn(true);
        when(TOTPUtil.isLocalUser(any(AuthenticationContext.class))).thenReturn(true);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
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

        when(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(any(), any())).thenCallRealMethod();
        when(mockedRuntimeParams.get(ENROL_USER_IN_AUTHENTICATIONFLOW)).thenReturn(isEnrolmentAllowedInRuntimeParams);

        if (isEnrolmentAllowedInRuntimeParams != null) {
            Assert.assertEquals(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context, mockedRuntimeParams),
                    Boolean.parseBoolean(isEnrolmentAllowedInRuntimeParams));
        } else {
            Assert.assertFalse(TOTPUtil.isEnrolUserInAuthenticationFlowEnabled(context, mockedRuntimeParams));
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
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
}
