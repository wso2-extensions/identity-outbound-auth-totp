//package org.wso2.carbon.identity.application.authenticator.totp.util;
//
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.apache.commons.lang.StringUtils;
//import org.w3c.dom.Document;
//import org.w3c.dom.Element;
//import org.w3c.dom.Node;
//import org.w3c.dom.NodeList;
//import org.wso2.carbon.context.PrivilegedCarbonContext;
//import org.wso2.carbon.context.RegistryType;
//import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
//import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
//import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
//import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
//import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
//import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
//import org.wso2.carbon.registry.core.Registry;
//import org.wso2.carbon.registry.core.Resource;
//import org.wso2.carbon.registry.core.exceptions.RegistryException;
//import org.xml.sax.SAXException;
//
//import javax.xml.parsers.DocumentBuilder;
//import javax.xml.parsers.DocumentBuilderFactory;
//import javax.xml.parsers.ParserConfigurationException;
//import java.io.ByteArrayInputStream;
//import java.io.IOException;
//import java.util.Map;
//
//
//public class TOTPRegistryUtil {
//    private static Log log = LogFactory.getLog(TOTPRegistryUtil.class);
//
////    private static  String encodingMethod = null;
////    private static  String timeStepSize = null;
////    private static  String windowSize = null;
////    private static  String enableTOTP = null;
////    private static  String usecase = null;
////    private static  String userAttribute = null;
////    private static  String secondaryUserstore = null;
//
////    static{
////
////        CarbonContext ccc = CarbonContext.getThreadLocalCarbonContext();
//////        AuthenticationContext context = new AuthenticationContext();
//////        String tenantDomainFromCon = context.getTenantDomain();
////        String tenantDomain = ccc.getTenantDomain();
////
//////        String tenantDomain = MultitenantUtils.getTenantDomain(username);
////
////        try {
////            loadXMLFromString(tenantDomain);
////        } catch (TOTPException e) {
////            e.printStackTrace();
////        }
////    }
//
//    /**
//     * Get stored encoding method.
//     *
//     * @return encodingMethod
//     */
//    public static String getEncodingMethod(String tenantDomain) {
//        String encodingMethods = null;
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            encodingMethods = getTOTPParameters().get("encodingMethod");
//        } else {
//            encodingMethods = "Base32";
//        }
//        if (TOTPAuthenticatorConstants.BASE32.equals(encodingMethods)) {
//            return TOTPAuthenticatorConstants.BASE32;
//        }
//        return TOTPAuthenticatorConstants.BASE64;
//    }
//
//    /**
//     * Get time step size.
//     *
//     * @return timeStepSize
//     * @throws TOTPException
//     */
//    public static long getTimeStepSize(AuthenticationContext context) throws TOTPException {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the time step size from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return Long.parseLong(getTOTPParameters().get("timeStepSize"));
//        } else {
//            String xmlFileContent= context.getProperty("xmlFileContent").toString();
//            if(StringUtils.isNotEmpty(xmlFileContent)){
//                return Long.parseLong(context.getProperty("timeStepSize").toString());
//            }
//            return Long.parseLong(getTOTPParameters().get("timeStepSize"));
//        }
//    }
//
//    /**
//     * Get stored window size.
//     *
//     * @return windowSize
//     * @throws TOTPException
//     */
//    public static int getWindowSize(AuthenticationContext context) throws TOTPException {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the window size from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return Integer.parseInt(getTOTPParameters().get("windowSize"));
//        } else {
//            String xmlFileContent= context.getProperty("xmlFileContent").toString();
//            if(StringUtils.isNotEmpty(xmlFileContent)) {
//                return Integer.parseInt(context.getProperty("windowSize").toString());
//            }
//            return Integer.parseInt(getTOTPParameters().get("windowSize"));
//        }
//    }
//
//    /**
//     * Check the totp enabled by admin
//     *
//     * @return enableTOTP
//     * @throws TOTPException
//     */
//    public static boolean checkTOTPEnableByAdmin(AuthenticationContext context) throws TOTPException {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the values of enableTOTP from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return Boolean.parseBoolean(getTOTPParameters().get("enableTOTP"));
//        } else {
//            String xmlFileContent = context.getProperty("xmlFileContent").toString();
//            if (StringUtils.isNotEmpty(xmlFileContent)) {
//                return Boolean.parseBoolean(context.getProperty("enableTOTP").toString());
//            }
//            return Boolean.parseBoolean(getTOTPParameters().get("enableTOTP"));
//        }
//    }
//
//    /**
//     * Get the secondary user store names.
//     *
//     * @param context Authentication context.
//     * @throws TOTPException
//     */
//    public static String getSecondaryUserStore(AuthenticationContext context) throws TOTPException {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the secondary user store from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return String.valueOf(getTOTPParameters().get("secondaryUserstore"));
//        } else {
//            String xmlFileContent = context.getProperty("xmlFileContent").toString();
//            if (StringUtils.isNotEmpty(xmlFileContent)) {
//                return context.getProperty("secondaryUserstore").toString();
//            }
//            return String.valueOf(getTOTPParameters().get("secondaryUserstore"));
//        }
//    }
//
//    /**
//     * Get the federated authenticator's user attribute.
//     *
//     * @param context Authentication context.
//     * @return user attribute
//     */
//    public static String getUserAttribute(AuthenticationContext context) {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the user attribute from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return String.valueOf(getTOTPParameters().get("userAttribute"));
//        } else {
//            String xmlFileContent = context.getProperty("xmlFileContent").toString();
//            if (StringUtils.isNotEmpty(xmlFileContent)) {
//                return context.getProperty("userAttribute").toString();
//            }
//            return String.valueOf(getTOTPParameters().get("userAttribute"));
//        }
//    }
//
//    /**
//     * Get usecase type which is used to get username
//     *
//     * @param context Authentication context.
//     * @return usecase type (local, association, userAttribute, subjectUri)
//     */
//    public static String getUsecase(AuthenticationContext context) {
//        if (log.isDebugEnabled()) {
//            log.debug("Read the usecase Type from properties file");
//        }
//        String tenantDomain = context.getTenantDomain();
//        if (tenantDomain.equals(TOTPAuthenticatorConstants.SUPER_TENANT_DOMAIN)) {
//            return String.valueOf(getTOTPParameters().get("usecase"));
//        } else {
//            String xmlFileContent = context.getProperty("xmlFileContent").toString();
//            if (StringUtils.isNotEmpty(xmlFileContent)) {
//                return context.getProperty("usecase").toString();
//            }
//            return String.valueOf(getTOTPParameters().get("usecase"));
//        }
//    }
//
//    /**
//     * Get xml file data from registry
//     *
//     * @throws TOTPException
//     */
//    public static String getRegistry(AuthenticationContext context) throws TOTPException {
//        System.out.println("Registry call to load xml file");
//        String tenantDomain = context.getTenantDomain();
//        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
//        String xmlContent;
//        try {
//            PrivilegedCarbonContext.startTenantFlow();
//            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
//            privilegedCarbonContext.setTenantId(tenantID);
//            privilegedCarbonContext.setTenantDomain(tenantDomain);
//            try {
//                Registry registry = (Registry) privilegedCarbonContext.getRegistry(RegistryType.SYSTEM_GOVERNANCE);
//                Resource resource = registry.get(TOTPAuthenticatorConstants.REGISTRY_PATH);
//                Object content = resource.getContent();
//                xmlContent = new String((byte[]) content);
//                context.setProperty("xmlFileContent", xmlContent);
//                return xmlContent;
//            } catch (RegistryException e) {
//                throw new TOTPException("Error when getting a resource in the path", e);
//            }
//        } finally {
//            PrivilegedCarbonContext.endTenantFlow();
//        }
//    }
//
//    /**
//     * Covert string type of xml content to xml document.
//     *
//     * @throws TOTPException
//     */
//    public static void loadXMLFromString(AuthenticationContext context) throws TOTPException {
//        String parameterValue = null;
//        String xml;
//        try {
//            xml = getRegistry(context);
//            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
//            factory.setNamespaceAware(true);
//            DocumentBuilder builder;
//            builder = factory.newDocumentBuilder();
//            Document doc;
//            doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
//            NodeList authConfigList = doc.getElementsByTagName("AuthenticatorConfig");
//            for (int authConfigIndex = 0; authConfigIndex < authConfigList.getLength(); authConfigIndex++) {
//                Node authConfigNode = authConfigList.item(authConfigIndex);
//                if (authConfigNode.getNodeType() == Node.ELEMENT_NODE) {
//                    Element authConfigElement = (Element) authConfigNode;
//                    String AuthConfig = authConfigElement.getAttribute("name");
//                    if (AuthConfig.equals("totp")) {
//                        NodeList AuthConfigChildList = authConfigElement.getChildNodes();
//                        for (int j = 0; j < AuthConfigChildList.getLength(); j++) {
//                            Node authConfigChildNode = AuthConfigChildList.item(j);
//                            if (authConfigChildNode.getNodeType() == Node.ELEMENT_NODE) {
//                                Element authConfigChildElement = (Element) authConfigChildNode;
//                                String tagAttribute = AuthConfigChildList.item(j).getAttributes().getNamedItem("name").getNodeValue();
//                                if (tagAttribute.equals("encodingMethod")) {
//                                    String encodingMethod = authConfigChildElement.getTextContent();
//                                    System.out.println("eeeeeeeeeeeeeeeeeeeeeeeeee" + encodingMethod);
//                                    context.setProperty("encodingMethod", encodingMethod);
//                                } else if (tagAttribute.equals("timeStepSize")) {
//                                    String timeStepSize = authConfigChildElement.getTextContent();
//                                    System.out.println("tttttttttttttttttttttttttt" + timeStepSize);
//                                    context.setProperty("timeStepSize", timeStepSize);
//                                } else if (tagAttribute.equals("windowSize")) {
//                                    String windowSize = authConfigChildElement.getTextContent();
//                                    System.out.println("wwwwwwwwwwwwwwwwwwwwwwwwwww" + windowSize);
//                                    context.setProperty("windowSize", windowSize);
//                                } else if (tagAttribute.equals("enableTOTP")) {
//                                    String enableTOTP = authConfigChildElement.getTextContent();
//                                    System.out.println("nnnnnnnnnnnnnnnnnnnnnnnnn" + enableTOTP);
//                                    context.setProperty("enableTOTP", enableTOTP);
//                                } else if (tagAttribute.equals("usecase")) {
//                                    String usecase = authConfigChildElement.getTextContent();
//                                    System.out.println("uuuuuuuuuuuuuuuuuuuuuuuuuuu" + usecase);
//                                    context.setProperty("usecase", usecase);
//                                } else if (tagAttribute.equals("userAttribute")) {
//                                    String userAttribute = authConfigChildElement.getTextContent();
//                                    System.out.println("aaaaaaaaaaaaaaaaaaaaaaaaaaa" + userAttribute);
//                                    context.setProperty("userAttribute", userAttribute);
//                                } else {
//                                    String secondaryUserstore = authConfigChildElement.getTextContent();
//                                    System.out.println("sssssssssssssssssssssssssssss" + secondaryUserstore);
//                                    context.setProperty("secondaryUserstore", secondaryUserstore);
//                                }
//                            }
//                        }
//                        break;
//                    }
//                }
//            }
//        } catch (SAXException | ParserConfigurationException | IOException e) {
//            throw new TOTPException("Unable to get the parameter value of ", e);
//        }
//    }
//
//    /**
//     * Get parameter values from local file.
//     */
//    private static Map<String, String> getTOTPParameters() {
//        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
//                .getAuthenticatorBean(TOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
//        return authConfig.getParameterMap();
//    }
//}
