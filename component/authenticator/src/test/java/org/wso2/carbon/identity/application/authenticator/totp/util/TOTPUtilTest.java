/*
 *  Copyright (c) 2017-2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
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

    // Static mocks
    private MockedStatic<FileBasedConfigurationBuilder> staticFileBasedConfigurationBuilder;
    private MockedStatic<IdentityHelperUtil> staticIdentityHelperUtil;
    private MockedStatic<ConfigurationFacade> staticConfigurationFacade;
    private MockedStatic<IdentityTenantUtil> staticIdentityTenantUtil;
    private MockedStatic<PrivilegedCarbonContext> staticPrivilegedCarbonContext;
    private MockedStatic<DocumentBuilderFactory> staticDocumentBuilderFactory;
    private MockedStatic<OrganizationManagementUtil> staticOrganizationManagementUtil;
    private MockedStatic<ServiceURLBuilder> staticServiceURLBuilder;
    private MockedStatic<TOTPDataHolder> staticTOTPDataHolder;

    @BeforeMethod
    public void setUp() {

        totpUtil = Mockito.spy(new TOTPUtil());

        MockitoAnnotations.openMocks(this);
        staticFileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
        staticIdentityHelperUtil = Mockito.mockStatic(IdentityHelperUtil.class);
        staticConfigurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
        staticIdentityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
        staticPrivilegedCarbonContext = Mockito.mockStatic(PrivilegedCarbonContext.class);
        staticDocumentBuilderFactory = Mockito.mockStatic(DocumentBuilderFactory.class);
        staticOrganizationManagementUtil = Mockito.mockStatic(OrganizationManagementUtil.class);
        staticServiceURLBuilder = Mockito.mockStatic(ServiceURLBuilder.class);
        staticTOTPDataHolder = Mockito.mockStatic(TOTPDataHolder.class);
        staticTOTPDataHolder.when(TOTPDataHolder::getInstance).thenReturn(dataHolder);
    }

    @AfterMethod
    public void tearDown() {
        if (staticServiceURLBuilder != null) staticServiceURLBuilder.close();
        if (staticOrganizationManagementUtil != null) staticOrganizationManagementUtil.close();
        if (staticDocumentBuilderFactory != null) staticDocumentBuilderFactory.close();
        if (staticPrivilegedCarbonContext != null) staticPrivilegedCarbonContext.close();
        if (staticIdentityTenantUtil != null) staticIdentityTenantUtil.close();
        if (staticConfigurationFacade != null) staticConfigurationFacade.close();
        if (staticIdentityHelperUtil != null) staticIdentityHelperUtil.close();
        if (staticFileBasedConfigurationBuilder != null) staticFileBasedConfigurationBuilder.close();
        if (staticTOTPDataHolder != null) staticTOTPDataHolder.close();
    }

    // Utility to invoke private methods via reflection (replaces PowerMock Whitebox)
    private static Object invokePrivate(Object target, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method m = target.getClass().getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return m.invoke(target, args);
    }

    // Utility to set private static fields via reflection
    private static void setStaticField(Class<?> clazz, String fieldName, Object value) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(null, value);
    }

    @Test
    public void testGetTOTPParameters() throws Exception {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.TOTP_AUTHENTICATION_ENDPOINT_URL,
                "totpauthenticationendpoint/custom/totp.jsp");
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);

        //test with empty parameters map.
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        Assert.assertNull(invokePrivate(totpUtil, "getTOTPParameters", new Class<?>[]{}));

        //test with non-empty parameters map.
        authenticatorConfig.setParameterMap(parameters);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        assertEquals(invokePrivate(totpUtil, "getTOTPParameters", new Class<?>[]{}), parameters);

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
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
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
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
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

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);

        assertEquals(invokePrivate(totpUtil, "getEnableTOTPPage",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
    }

    @Test(description = "Test case for getEnableTOTPPageFromXMLFile(): getEnableTOTPPage from registry file.")
    public void testGetEnableTOTPPageFromXMLFile() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).
                thenReturn(TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
        assertEquals(invokePrivate(totpUtil, "getEnableTOTPPage",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
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

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        assertEquals(invokePrivate(totpUtil, "getEnableTOTPPage",
                new Class<?>[]{AuthenticationContext.class}, authenticationContext), TOTPAuthenticatorConstants.ENABLE_TOTP_REQUEST_PAGE);
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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        assertEquals(TOTPUtil.getWindowSize(authenticationContext), 5);
    }

    @Test
    public void testRedirectToEnableTOTPReqPage() throws Exception {

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
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);

        // Mock OrganizationManager to prevent NPE in getOrganizationId()
        OrganizationManager mockedOrganizationManager = Mockito.mock(OrganizationManager.class);
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(mockedOrganizationManager);
        Mockito.when(mockedOrganizationManager.resolveOrganizationId(anyString())).thenReturn(null);
        setStaticField(TOTPUtil.class, "DATA_HOLDER", dataHolder);

        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testRedirectToEnableTOTPReqPageForTenant() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(TOTPAuthenticatorConstants.GET_PROPERTY_FROM_IDENTITY_CONFIG, null);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.AUTHENTICATION,
                TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        authenticationContext.setProperty(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "false");
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENROL_USER_IN_AUTHENTICATIONFLOW, "true");
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);

        // Mock OrganizationManager to prevent NPE in getOrganizationId()
        OrganizationManager mockedOrganizationManager = Mockito.mock(OrganizationManager.class);
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(mockedOrganizationManager);
        Mockito.when(mockedOrganizationManager.resolveOrganizationId(anyString())).thenReturn(null);
        setStaticField(TOTPUtil.class, "DATA_HOLDER", dataHolder);

        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test()
    public void testRedirectToEnableTOTPReqPageForSuperTenantEntrol()
            throws Exception {

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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setParameterMap(parameters);
        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(TOTPAuthenticatorConstants.LOGIN_PAGE);
        doNothing().when(httpServletResponse).sendRedirect(anyString());

        // Mock OrganizationManager to prevent NPE in getOrganizationId()
        OrganizationManager mockedOrganizationManager = Mockito.mock(OrganizationManager.class);
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(mockedOrganizationManager);
        Mockito.when(mockedOrganizationManager.resolveOrganizationId(anyString())).thenReturn(null);
        setStaticField(TOTPUtil.class, "DATA_HOLDER", dataHolder);

        TOTPUtil.redirectToEnableTOTPReqPage(httpServletResponse, authenticationContext,
                TOTPAuthenticatorConstants.QR_CODE_CLAIM_URL);
    }

    @Test(description = "Test case for getEncodingMethod() for super tenant user")
    public void testGetEncodingMethodWithContex() throws AuthenticationFailedException {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(TOTPAuthenticatorConstants.ENCODING_METHOD,
                TOTPAuthenticatorConstants.BASE64);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
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
        staticIdentityHelperUtil.when(() -> IdentityHelperUtil.getAuthenticatorParameters(anyString())).thenReturn(parameters);
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
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
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

        staticIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        staticIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
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

        staticIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        staticIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
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

        staticIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        staticIdentityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn(tenantDomain);

        staticConfigurationFacade.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
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
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        staticServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    @Test
    void testGetTOTPIssuerDisplayName_FromParameters() throws TOTPException {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        Map<String, String> mockParameters = new HashMap<>();
        mockParameters.put(TOTPAuthenticatorConstants.TOTP_COMMON_ISSUER, "true");
        mockParameters.put(TOTPAuthenticatorConstants.TOTP_ISSUER, "IssuerFromParams");

        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        Mockito.when(fileBasedConfigurationBuilder.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME)).thenReturn(mockAuthConfig);
        Mockito.when(mockAuthConfig.getParameterMap()).thenReturn(mockParameters);

        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals("IssuerFromParams", result);
    }

    @Test
    public void testGetIssuerFromBranding_BrandingEnabled() throws Exception {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
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

        Mockito.when(dataHolder.getBrandingPreferenceManager()).thenReturn(mockBrandingManager);
        when(mockBrandingManager.resolveBrandingPreference(anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(brandingPreference);

        setStaticField(TOTPUtil.class, "DATA_HOLDER", dataHolder);

        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals(result, "BrandedIssuer");
    }

    @Test
    public void testGetIssuerFromBranding_BrandingDisabled() throws Exception {

        AuthenticatorConfig mockAuthConfig = Mockito.mock(AuthenticatorConfig.class);
        staticFileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(fileBasedConfigurationBuilder);
        Mockito.when(fileBasedConfigurationBuilder.getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME))
                .thenReturn(mockAuthConfig);
        Mockito.when(mockAuthConfig.getParameterMap()).thenReturn(new HashMap<>());

        BrandingPreferenceManager mockBrandingManager = Mockito.mock(BrandingPreferenceManager.class);
        BrandingPreference brandingPreference = new BrandingPreference();
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectNode preferenceNode = objectMapper.createObjectNode();
        preferenceNode.putObject("configs").put("isBrandingEnabled", false);
        brandingPreference.setPreference(preferenceNode);

        Mockito.when(dataHolder.getBrandingPreferenceManager()).thenReturn(mockBrandingManager);
        PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
        Registry mockRegistry = Mockito.mock(Registry.class);
        Resource mockResource = Mockito.mock(Resource.class);

        staticPrivilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
        when(mockBrandingManager.resolveBrandingPreference(anyString(), anyString(), anyString(), anyBoolean()))
                .thenReturn(brandingPreference);
        doNothing().when(privilegedCarbonContext).setTenantId(anyInt());
        staticPrivilegedCarbonContext.when(PrivilegedCarbonContext::endTenantFlow).thenAnswer(inv -> null);
        when(privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE)).thenReturn(mockRegistry);
        when(mockRegistry.get(anyString())).thenReturn(mockResource);
        when(mockResource.getContent()).thenReturn(new byte[0]);

        DocumentBuilderFactory mockedDocumentBuilderFactory = Mockito.mock(DocumentBuilderFactory.class);
        staticDocumentBuilderFactory.when(DocumentBuilderFactory::newInstance).thenReturn(mockedDocumentBuilderFactory);
        DocumentBuilder mockedDocumentBuilder = Mockito.mock(DocumentBuilder.class);
        when(mockedDocumentBuilderFactory.newDocumentBuilder()).thenReturn(mockedDocumentBuilder);
        Document mockedDocument = Mockito.mock(Document.class);
        when(mockedDocumentBuilder.parse(any(ByteArrayInputStream.class))).thenReturn(mockedDocument);

        NodeList emptyNodeList = Mockito.mock(NodeList.class);
        Mockito.when(emptyNodeList.getLength()).thenReturn(0);
        when(mockedDocument.getElementsByTagName("AuthenticatorConfig")).thenReturn(emptyNodeList);

        setStaticField(TOTPUtil.class, "DATA_HOLDER", dataHolder);

        // Mock OrganizationManager to return null initially, so the fallback to tenantDomain is used
        OrganizationManager mockedOrganizationManager = Mockito.mock(OrganizationManager.class);
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(null);

        String result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        // When branding is disabled, issuer is null, context is null, registry returns empty.
        // If OrganizationManager is null, it falls back to tenantDomain.
        assertEquals(result, "example.com");

        // Now test when organizationManager is present and resolves an org ID and name
        Mockito.when(dataHolder.getOrganizationManager()).thenReturn(mockedOrganizationManager);
        Mockito.when(mockedOrganizationManager.resolveOrganizationId(anyString())).thenReturn("123");
        Mockito.when(mockedOrganizationManager.getOrganizationNameById(anyString())).thenReturn("org1");
        result = TOTPUtil.getTOTPIssuerDisplayName("example.com", null);
        assertEquals(result, "org1");
    }
}
