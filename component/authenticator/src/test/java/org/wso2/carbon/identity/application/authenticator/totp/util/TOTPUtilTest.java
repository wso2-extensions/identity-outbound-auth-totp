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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.mockito.Mock;
import org.mockito.Mockito;
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
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.internal.TOTPDataHolder;
import org.wso2.carbon.identity.branding.preference.management.core.BrandingPreferenceManager;
import org.wso2.carbon.identity.branding.preference.management.core.exception.BrandingPreferenceMgtException;
import org.wso2.carbon.identity.branding.preference.management.core.model.BrandingPreference;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityHelperUtil.class, ConfigurationFacade.class,
        IdentityTenantUtil.class, ServiceURLBuilder.class, TOTPDataHolder.class, PrivilegedCarbonContext.class,
        DocumentBuilderFactory.class, OrganizationManagementUtil.class})
@WithCarbonHome
@PowerMockIgnore({"org.mockito.*", "org.powermock.api.mockito.invocation.*"})
public class TOTPUtilTest {

    private TOTPUtil totpUtil;

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
    private TOTPDataHolder dataHolder;

    @BeforeMethod
    public void setUp() {

        totpUtil = spy(new TOTPUtil());

        initMocks(this);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(IdentityHelperUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(TOTPDataHolder.class);
        mockStatic(PrivilegedCarbonContext.class);
        mockStatic(DocumentBuilderFactory.class);
        mockStatic(OrganizationManagementUtil.class);
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
        assertEquals(Whitebox.invokeMethod(totpUtil, "getTOTPParameters"), parameters);

    }

    @Test
    public void testGetLoginPageFromXMLFile() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL,
                "totpauthenticationendpoint/custom/totp.jsp");
        assertEquals(
                TOTPUtil.getLoginPageFromXMLFile(authenticationContext, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME),
                "totpauthenticationendpoint/custom/totp.jsp");
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

        assertEquals(
                TOTPUtil.getLoginPageFromXMLFile(authenticationContext, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME),
                "totpauthenticationendpoint/custom/totp.jsp");
    }

    @Test(description = "Test case for getErrorPageFromXMLFile(): getErrorPage from registry file.")
    public void testGetErrorPageFromXMLFile() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ERROR_PAGE_URL,
                "totpauthenticationendpoint/custom/error.jsp");
        assertEquals(TOTPUtil.getErrorPageFromXMLFile(authenticationContext,
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

        assertEquals(TOTPUtil.getErrorPageFromXMLFile(authenticationContext,
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

        assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
                authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "Test case for getEnableTOTPPageFromXMLFile(): getEnableTOTPPage from registry file.")
    public void testGetEnableTOTPPageFromXMLFile() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).
                thenReturn(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
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
        assertEquals(Whitebox.invokeMethod(totpUtil, "getEnableTOTPPage",
                authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "Test case for getTimeStepSize with super tenant use case")
    public void testGetTimeStepSizeForTenant() {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.TIME_STEP_SIZE, 30);
        assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 30);
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
        assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 60);
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
        assertEquals(TOTPUtil.getTimeStepSize(authenticationContext), 60);
    }

    @Test(description = "Test case for getWindowSize with tenant use case")
    public void testGetWindowSizeForTenant() {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.WINDOW_SIZE,
                3);
        assertEquals(TOTPUtil.getWindowSize(authenticationContext), 3);
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
        assertEquals(TOTPUtil.getWindowSize(authenticationContext), 5);
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
        assertEquals(TOTPUtil.getWindowSize(authenticationContext), 5);
    }

    @Test
    public void testRedirectToEnableTOTPReqPage() throws AuthenticationFailedException {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        authenticationContext.setTenantDomain(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG, null);
        authenticationContext
                .setProperty(TOTPAuthenticatorConstants.AUTHENTICATION, TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
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
    public void testRedirectToEnableTOTPReqPageForSuperTenantEntrol()
            throws AuthenticationFailedException, IOException {

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
        assertEquals(TOTPUtil.getEncodingMethod(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN, context),
                TOTPAuthenticatorConstants.BASE64);
    }

    @Test(description = "Test case for getEncodingMethod() for tenant user from local file.")
    public void testGetEncodingMethodFromRLocalFile() {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE32);
        assertEquals(TOTPUtil.getEncodingMethod("wso2.org", authenticationContext),
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
        assertEquals(TOTPUtil.getEncodingMethod("wso2.org", authenticationContext),
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
        assertEquals(TOTPUtil.getEncodingMethod(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN),
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
        assertEquals(TOTPUtil.getMultiOptionURIQueryParam(httpServletRequest), expected);
    }

    @DataProvider(name = "enableTOTPPageTestDataProvider")
    public static Object[][] getEnableTOTPPageTestData() {

        return new Object[][]{
                {"carbon.super",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_enroll.do"},
                {"carbon.super",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_enroll.do"},
                {"wso2.com",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_enroll.do"},
                {"wso2.com",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/t/wso2.com/authenticationendpoint/totp_enroll.do"},
        };
    }

    @Test(description = "Test case for getEnableTOTPPage()", dataProvider = "enableTOTPPageTestDataProvider")
    public void testGetTOTPEnablePage(String tenantDomain, String urlFromConfig,
                                      String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(urlFromConfig);
        mockServiceURLBuilder();

        assertEquals(TOTPUtil.getEnableTOTPPage(new AuthenticationContext()), expectedURL);
    }

    @DataProvider(name = "loginPageTestDataProvider")
    public static Object[][] getLoginPageTestData() {

        return new Object[][]{
                {"carbon.super",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp.do"},
                {"carbon.super",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp.do"},
                {"wso2.com",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp.do"},
                {"wso2.com",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/t/wso2.com/authenticationendpoint/totp.do"},
        };
    }

    @Test(description = "Test case for getTOTPLoginPage()", dataProvider = "loginPageTestDataProvider")
    public void testGetTOTPLoginPage(String tenantDomain, String urlFromConfig,
                                     String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(urlFromConfig);
        mockServiceURLBuilder();

        assertEquals(TOTPUtil.getTOTPLoginPage(new AuthenticationContext()), expectedURL);
    }

    @DataProvider(name = "errorPageTestDataProvider")
    public static Object[][] getErrorPageTestData() {

        return new Object[][]{
                {"carbon.super",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_error.do"},
                {"carbon.super",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_error.do"},
                {"wso2.com",
                        "https://localhost:9443/authenticationendpoint/login.do",
                        "https://localhost:9443/authenticationendpoint/totp_error.do"},
                {"wso2.com",
                        "authenticationendpoint/login.do",
                        "https://localhost:9443/t/wso2.com/authenticationendpoint/totp_error.do"},
        };
    }

    @Test(description = "Test case for getTOTPErrorPage()", dataProvider = "errorPageTestDataProvider")
    public void testGetTOTPErrorPage(String tenantDomain, String urlFromConfig,
                                     String expectedURL) throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomainFromContext()).thenReturn(tenantDomain);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(urlFromConfig);
        mockServiceURLBuilder();

        // ConfigurationFacade will return a tenant qualified URL if tenant qualified URLs are enabled.
        assertEquals(TOTPUtil.getTOTPErrorPage(new AuthenticationContext()), expectedURL);
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

                String tenantFromContext = IdentityTenantUtil.getTenantDomainFromContext();
                if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantFromContext)) {
                    path = "/t/" + tenantFromContext + path;
                }
                PowerMockito.when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                PowerMockito.when(serviceURL.getRelativePublicURL()).thenReturn(path);
                PowerMockito.when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockStatic(ServiceURLBuilder.class);
        PowerMockito.when(ServiceURLBuilder.create()).thenReturn(builder);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    @Test
    void testGetTOTPIssuerDisplayName_FromParameters() throws TOTPException {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        Map<String, String> mockParameters = new HashMap<>();
        mockParameters.put(TOTPAuthenticatorConstants.TOTP_COMMON_ISSUER, "true");
        mockParameters.put(TOTPAuthenticatorConstants.TOTP_ISSUER, "IssuerFromParams");

        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        Mockito.when(fileBasedConfigurationBuilder.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)).thenReturn(mockAuthConfig);
        Mockito.when(mockAuthConfig.getParameterMap()).thenReturn(mockParameters);

        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals("IssuerFromParams", result);
    }

    @Test
    public void testGetIssuerFromBranding_BrandingEnabled() throws TOTPException, BrandingPreferenceMgtException {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        Mockito.when(fileBasedConfigurationBuilder.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME))
                .thenReturn(mockAuthConfig);
        Mockito.when(mockAuthConfig.getParameterMap()).thenReturn(new HashMap<>());

        BrandingPreferenceManager mockBrandingManager = Mockito.mock(BrandingPreferenceManager.class);
        BrandingPreference brandingPreference = new BrandingPreference();
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode preferenceNode = objectMapper.createObjectNode();
        preferenceNode.putObject("configs").put("isBrandingEnabled", true);
        preferenceNode.putObject("organizationDetails").put("displayName", "BrandedIssuer");
        brandingPreference.setPreference(preferenceNode);

        Mockito.when(TOTPDataHolder.getInstance()).thenReturn(dataHolder);
        Mockito.when(dataHolder.getBrandingPreferenceManager()).thenReturn(mockBrandingManager);
        when(mockBrandingManager.resolveBrandingPreference(anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(brandingPreference);

        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals(result, "BrandedIssuer");
    }

    @Test
    public void testGetIssuerFromBranding_BrandingDisabled() throws Exception {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        Mockito.when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        Mockito.when(fileBasedConfigurationBuilder.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME))
                .thenReturn(mockAuthConfig);
        Mockito.when(mockAuthConfig.getParameterMap()).thenReturn(new HashMap<>());

        BrandingPreferenceManager mockBrandingManager = Mockito.mock(BrandingPreferenceManager.class);
        BrandingPreference brandingPreference = new BrandingPreference();
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode preferenceNode = objectMapper.createObjectNode();
        preferenceNode.putObject("configs").put("isBrandingEnabled", false);
        brandingPreference.setPreference(preferenceNode);

        Mockito.when(TOTPDataHolder.getInstance()).thenReturn(dataHolder);
        Mockito.when(dataHolder.getBrandingPreferenceManager()).thenReturn(mockBrandingManager);
        PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
        Registry mockRegistry = Mockito.mock(Registry.class);
        Resource mockResource = Mockito.mock(Resource.class);

        Mockito.when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        when(mockBrandingManager.resolveBrandingPreference(anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(brandingPreference);
        doNothing().when(privilegedCarbonContext, "setTenantId", anyInt());
        doNothing().when(PrivilegedCarbonContext.class, "endTenantFlow");
        when(privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE)).thenReturn(mockRegistry);
        when(mockRegistry.get(anyString())).thenReturn(mockResource);
        when(mockResource.getContent()).thenReturn(new byte[0]);

        DocumentBuilderFactory mockedDocumentBuilderFactory = Mockito.mock(DocumentBuilderFactory.class);
        when(DocumentBuilderFactory.newInstance()).thenReturn(mockedDocumentBuilderFactory);
        DocumentBuilder mockedDocumentBuilder = Mockito.mock(DocumentBuilder.class);
        when(mockedDocumentBuilderFactory.newDocumentBuilder()).thenReturn(mockedDocumentBuilder);
        Document mockedDocument = Mockito.mock(Document.class);
        when(mockedDocumentBuilder.parse(any(ByteArrayInputStream.class))).thenReturn(mockedDocument);

        NodeList emptyNodeList = Mockito.mock(NodeList.class);
        Mockito.when(emptyNodeList.getLength()).thenReturn(0);
        when(mockedDocument.getElementsByTagName("AuthenticatorConfig")).thenReturn(emptyNodeList);

        Mockito.when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(false);
        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals(result, "example.com");

        Mockito.when(OrganizationManagementUtil.isOrganization(anyString())).thenReturn(true);
        OrganizationManager mockedOrganizationManager = Mockito.mock(OrganizationManager.class);
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(mockedOrganizationManager);
        Mockito.when(mockedOrganizationManager.resolveOrganizationId(anyString())).thenReturn("123");
        Mockito.when(mockedOrganizationManager.getOrganizationNameById(anyString())).thenReturn("org1");
        result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals(result, "org1");
    }

   /* @Test(description = "Test case for getProcessedClaimValue()", dataProvider = "processedClaimValueTestDataProvider")
    public void testGetProcessedClaimValue(String claimURI, Map<String, String> claimProperties, String claimValue,
                                           String expectedClaimValue) throws Exception {

        1st approach
        spy(TOTPUtil.class);
        given(TOTPUtil.getClaimProperties("testDomain", claimURI)).willReturn(claimProperties);

        2nd approach
        doReturn(claimProperties).when(totpUtil).getClaimProperties("testDomain", claimURI);
        when(totpUtil.getClaimProperties("testDomain", claimURI)).thenReturn(claimProperties);

        3rd approach
        mockStatic(TOTPUtil.class);
        TOTPUtil totpUtilSpy = spy(new TOTPUtil());
        when(TOTPUtil.getClaimProperties("testDomain", "claimURI")).thenReturn(claimProperties);
        String processedClaimValue = totpUtilSpy.getProcessedClaimValue(claimURI, claimValue, "testDomain");

        4th approach
        TOTPUtil totpUtilMocked = Mockito.mock(TOTPUtil.class, Mockito.CALLS_REAL_METHODS);

        String processedClaimValue = totpUtil.getProcessedClaimValue(claimURI, claimValue, "testDomain");

        // Verify the result
        assertEquals(expectedClaimValue, processedClaimValue);
    }

    @DataProvider(name = "processedClaimValueTestDataProvider")
    public static Object[][] getProcessedClaimValueTestData() {

        HashMap<String, String> claimProperties_1 = new HashMap<>();
        claimProperties_1.put("EnableEncryption", "true");

        HashMap<String, String> claimProperties_2 = new HashMap<>();
        claimProperties_2.put("EnableEncryption", "false");

        HashMap<String, String> claimProperties_3 = new HashMap<>();


        return new Object[][]{
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, claimProperties_1, "AER2BRI0LK4XCSC1", "AER2BRI0LK4XCSC1"},
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, claimProperties_1, "", ""},
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, claimProperties_2, "AER2BRI0LK4XCSC1", "AER2BRI0LK4XCSC1"},
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, claimProperties_2, "", ""},
                {TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, claimProperties_3, "", ""},
        };
    }*/
}
