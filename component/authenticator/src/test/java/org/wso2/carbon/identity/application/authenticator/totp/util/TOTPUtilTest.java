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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityHelperUtil.class, ConfigurationFacade.class,
        IdentityTenantUtil.class})
public class TOTPUtilTest {
    private TOTPUtil totpUtil;
    AuthenticationContext authenticationContext;
    @Mock
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @Mock
    private ConfigurationFacade configurationFacade;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private AuthenticationContext context;

    @Mock
    private RealmService realmService;

    @Mock
    private IdentityHelperUtil identityHelperUtil;

    @BeforeMethod
    public void setUp() {
        totpUtil = new TOTPUtil();
        initMocks(this);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(IdentityHelperUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(IdentityHelperUtil.class);
    }

    @Test
    public void testGetTOTPParameters() throws Exception {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL,
                "totpauthenticationendpoint/custom/totp.jsp");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);

        //test with empty parameters map.
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertNull(Whitebox.invokeMethod(totpUtil, "getTOTPParameters"));

        //test with non-empty parameters map.
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(Whitebox.invokeMethod(totpUtil, "getTOTPParameters"), parameters);

    }

    @Test
    public void testGetLoginPageFromXMLFile() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL, "totpauthenticationendpoint/custom/totp.jsp");
        Assert.assertEquals(TOTPUtil.getLoginPageFromXMLFile(authenticationContext, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME), "totpauthenticationendpoint/custom/totp.jsp");
    }

    @Test(description = "getLoginPage from local file.")
    public void testGetLoginPage() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        parameters.put(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL,
                "totpauthenticationendpoint/custom/totp.jsp");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        Assert.assertEquals(TOTPUtil.getLoginPageFromXMLFile(authenticationContext, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME), "totpauthenticationendpoint/custom/totp.jsp");
    }

    @Test(description = "Test case for getErrorPageFromXMLFile(): getErrorPage from registry file.")
    public void testGetErrorPageFromXMLFile() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL,
                "totpauthenticationendpoint/custom/error.jsp");
        Assert.assertEquals(TOTPUtil.getErrorPageFromXMLFile(authenticationContext,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME), "totpauthenticationendpoint/custom/error.jsp");
    }

    @Test(description = "Test case for getErrorPageFromXMLFile(): getErrorPage from local file.")
    public void testGetErrorPageFromXMLFileForSuperTenant() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        parameters.put(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL,
                "totpauthenticationendpoint/custom/error.jsp");
        authenticatorConfig.setParameterMap(parameters);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        Assert.assertEquals(TOTPUtil.getErrorPageFromXMLFile(authenticationContext,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME), "totpauthenticationendpoint/custom/error.jsp");
    }

    @Test(description = "Test case for getEnableTOTPPageFromXMLFile(): getEnableTOTPPage from registry file.")
    public void testGetEnableTOTPPageFromRgistry() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL,
                TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);

        Assert.assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
                authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "Test case for getEnableTOTPPageFromXMLFile(): getEnableTOTPPage from registry file.")
    public void testGetEnableTOTPPageFromXMLFile() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).
                thenReturn(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        Assert.assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
                authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "TOTPAuthenticator:getEnableTOTPPage() test for get the enableTOTPPage url from authentication.xml file.")
    public void testGetEnableTOTPPage() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY,
                IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        parameters.put(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL,
                TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        authenticatorConfig.setParameterMap(parameters);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
                authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "Test case for getTimeStepSize with super tenant use case")
    public void testGetTimeStepSizeForTenant() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TIME_STEP_SIZE, 30);
        Assert.assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 30);
    }

    @Test(description = "Test case for getTimeStepSize with super tenant use case")
    public void testGetTimeStepSizeForSuperTenant() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.TIME_STEP_SIZE, "60");
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        Assert.assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 60);
    }

    @Test(description = "Test case for getTimeStepSize from identityConfig")
    public void testGetTimeStepSize() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
                TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.TIME_STEP_SIZE, "60");
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        Assert.assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 60);
    }

    @Test(description = "Test case for getWindowSize with tenant use case")
    public void testGetWindowSizeForTenant() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.WINDOW_SIZE,
                3);
        Assert.assertEquals(TOTPUtil.getWindowSize(authenticationContext), 3);
    }

    @Test(description = "Test case for getWindowSize with super tenant use case")
    public void testGetWindowSizeForSuperTenant() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.WINDOW_SIZE, "5");
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        Assert.assertEquals(TOTPUtil.getWindowSize(authenticationContext), 5);
    }

    @Test(description = "Test case for getWindowSize from identityConfig")
    public void testGetWindowSizeFromIdentityConfig() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
                TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.WINDOW_SIZE, "5");
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        Assert.assertEquals(TOTPUtil.getWindowSize(authenticationContext), 5);
    }

    @Test
    public void testRedirectToEnableTOTPReqPage() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG, null);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        parameters.put(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "true");
        parameters.put(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL,
                "totpauthenticationendpoint/custom/totp.jsp");
        parameters.put(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL,
                TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        authenticatorConfig.setParameterMap(parameters);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);
        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testRedirectToEnableTOTPReqPageForTenant() throws AuthenticationFailedException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG, null);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "false");
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "true");
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test()
    public void testRedirectToEnableTOTPReqPageForSuperTenantEntrol() throws AuthenticationFailedException, IOException {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG, null);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "true");
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "true");
        parameters.put(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE_URL,
                TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setParameterMap(parameters);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);
        doNothing().when(httpServletResponse).sendRedirect(anyString());
        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test(description = "Test case for getEncodingMethod() for super tenant user")
    public void testGetEncodingMethodWithContex() throws AuthenticationFailedException {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE64);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(TOTPUtil.getEncodingMethod(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN, context),
                TOTPAuthenticatorConstants.BASE64);
    }

    @Test(description = "Test case for getEncodingMethod() for tenant user from local file.")
    public void testGetEncodingMethodFromRLocalFile() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE32);
        Assert.assertEquals(TOTPUtil.getEncodingMethod("wso2.org", authenticationContext),
                TOTPAuthenticatorConstants.BASE32);
    }

    @Test(description = "Test case for getEncodingMethod() for tenant user from registry.")
    public void testGetEncodingMethodFromRegistry() {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE32);
        when(IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG,
                TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG);
        Assert.assertEquals(TOTPUtil.getEncodingMethod("wso2.org", authenticationContext),
                TOTPAuthenticatorConstants.BASE32);
    }

    @Test(description = "Test case for getEncodingMethod() for super tenant user")
    public void testGetEncodingMethod() throws AuthenticationFailedException {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE64);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertEquals(TOTPUtil.getEncodingMethod(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN),
                TOTPAuthenticatorConstants.BASE64);
    }

    @DataProvider(name = "multiOptionURIValueProvider")
    public static Object[][] getMultiOptionURIValue() {

        return new Object[][]{
                {null, ""},
                {"", "&multiOptionURI="},
                {"https://localhost:9443/samlsso", "&multiOptionURI=https%3A%2F%2Flocalhost%3A9443%2Fsamlsso"}
        };
    }

    @Test(description = "Test case for getMultiOptionURIQueryParam()", dataProvider = "multiOptionURIValueProvider")
    public void testGetMultiOptionURIQueryParam(String requestParamValue, String expected) {

        when(httpServletRequest.getParameter("multiOptionURI")).thenReturn(requestParamValue);
        Assert.assertEquals(TOTPUtil.getMultiOptionURIQueryParam(httpServletRequest), expected);
    }

    @Test(description = "Test case for getDefaultTOTPEnablePage()")
    public void testGetDefaultTOTPEnablePage() {

        String loginPageURL = "https://localhost:9443/authenticationendpoint/login.do";
        String enableTOTPURL = "https://localhost:9443/totpauthenticationendpoint/enableTOTP.jsp";

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(loginPageURL);

        Assert.assertEquals(TOTPUtil.getDefaultTOTPEnablePage(), enableTOTPURL);
    }

    @Test(description = "Test case for getDefaultTOTPLoginPage()")
    public void testGetDefaultTOTPLoginPage() {

        String loginPageURL = "https://localhost:9443/authenticationendpoint/login.do";
        String expectedURL = "https://localhost:9443/totpauthenticationendpoint/totp.jsp";

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(loginPageURL);

        Assert.assertEquals(TOTPUtil.getDefaultTOTPLoginPage(), expectedURL);
    }

    @Test(description = "Test case for getDefaultTOTPErrorPage()")
    public void testGetDefaultTOTPErrorPage() {

        String loginPageURL = "https://localhost:9443/authenticationendpoint/login.do";
        String expectedURL = "https://localhost:9443/totpauthenticationendpoint/totpError.jsp";

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(loginPageURL);

        Assert.assertEquals(TOTPUtil.getDefaultTOTPErrorPage(), expectedURL);
    }



    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
