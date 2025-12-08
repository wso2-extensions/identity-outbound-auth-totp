package org.wso2.carbon.identity.application.authenticator.totp;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class TOTPAuthenticatorConfigImpl implements IdentityConnectorConfig {

    private static final String CONNECTOR_NAME = "totp";
    private static final String CATEGORY = "Multi Factor Authenticators";
    private static final String FRIENDLY_NAME = "TOTP Authenticator";
    private static final String SUB_CATEGORY = "DEFAULT";
    
    // The key used to store the config
    public static final String ENROLL_USER_IN_FLOW_CONFIG = "TOTP.EnrolUserInAuthenticationFlow";

    @Override
    public String getName() {
        return CONNECTOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {
        return CATEGORY;
    }

    @Override
    public String getSubCategory() {
        return SUB_CATEGORY;
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(ENROLL_USER_IN_FLOW_CONFIG, "Enable TOTP Device Progressive Enrollment");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(ENROLL_USER_IN_FLOW_CONFIG, 
            "Allow users to enroll TOTP devices during the authentication flow.");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {
        return new String[]{ENROLL_USER_IN_FLOW_CONFIG};
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        // Default is true to maintain backward compatibility
        Properties properties = new Properties();
        properties.setProperty(ENROLL_USER_IN_FLOW_CONFIG, "true"); 
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain) 
            throws IdentityGovernanceException {
        Map<String, String> defaultValues = new HashMap<>();
        for (String propertyName : propertyNames) {
            if (ENROLL_USER_IN_FLOW_CONFIG.equals(propertyName)) {
                defaultValues.put(propertyName, "true");
            }
        }
        return defaultValues;
    }
}
