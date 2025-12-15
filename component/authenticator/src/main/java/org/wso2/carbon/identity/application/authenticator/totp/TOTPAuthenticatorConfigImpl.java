/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.totp;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Configuration implementation for TOTP Authenticator.
 * This class provides organization-level configuration for TOTP progressive enrollment.
 */
public class TOTPAuthenticatorConfigImpl implements IdentityConnectorConfig {
    
    private static final String CONNECTOR_NAME = "totp";
    private static final String CATEGORY = "Multi Factor Authenticators";
    private static final String FRIENDLY_NAME = "TOTP Authenticator";
    private static final String SUB_CATEGORY = "DEFAULT";
    
    // The key used to store the config
    public static final String ENROLL_USER_IN_FLOW_CONFIG = "TOTP.EnrolUserInAuthenticationFlow";

    /**
     * Get the connector name.
     * 
     * @return The connector name
     */
    @Override
    public String getName() {

        return CONNECTOR_NAME;
    }

    /**
     * Get the friendly name of the connector.
     * 
     * @return The friendly name
     */
    @Override
    public String getFriendlyName() {

        return FRIENDLY_NAME;
    }

    /**
     * Get the category of the connector.
     * 
     * @return The category
     */
    @Override
    public String getCategory() {

        return CATEGORY;
    }

    /**
     * Get the sub-category of the connector.
     * 
     * @return The sub-category
     */
    @Override
    public String getSubCategory() {

        return SUB_CATEGORY;
    }

    /**
     * Get the order of the connector for UI display.
     * 
     * @return The order value
     */
    @Override
    public int getOrder() {

        return 0;
    }

    /**
     * Get the mapping of property keys to display names.
     * 
     * @return Map of property name to display name
     */
    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(ENROLL_USER_IN_FLOW_CONFIG, "Enable TOTP Device Progressive Enrollment");
        return nameMapping;
    }

    /**
     * Get the mapping of property keys to descriptions.
     * 
     * @return Map of property name to description
     */
    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(ENROLL_USER_IN_FLOW_CONFIG, 
            "Allow users to enroll TOTP devices during the authentication flow. " +
            "When enabled, users without TOTP configured will be prompted to set it up during login.");
        return descriptionMapping;
    }

    /**
     * Get the list of property names managed by this connector.
     * 
     * @return Array of property names
     */
    @Override
    public String[] getPropertyNames() {
        
        return new String[]{ENROLL_USER_IN_FLOW_CONFIG};
    }

    /**
     * Get default property values for the given tenant.
     * 
     * @param tenantDomain The tenant domain
     * @return Properties with default values
     * @throws IdentityGovernanceException If an error occurs while retrieving default values
     */
    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        
        // Input validation
        if (tenantDomain == null || tenantDomain.trim().isEmpty()) {
            throw new IdentityGovernanceException("Tenant domain cannot be null or empty");
        }
        
        // Default is true to maintain backward compatibility
        Properties properties = new Properties();
        properties.setProperty(ENROLL_USER_IN_FLOW_CONFIG, "true"); 
        return properties;
    }

    /**
     * Get default values for specific properties.
     * 
     * @param propertyNames Array of property names to get defaults for
     * @param tenantDomain The tenant domain
     * @return Map of property name to default value
     * @throws IdentityGovernanceException If an error occurs while retrieving default values
     */
    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain) 
            throws IdentityGovernanceException {
        
        // Input validation
        if (propertyNames == null) {
            throw new IdentityGovernanceException("Property names array cannot be null");
        }
        
        if (tenantDomain == null || tenantDomain.trim().isEmpty()) {
            throw new IdentityGovernanceException("Tenant domain cannot be null or empty");
        }
        
        Map<String, String> defaultValues = new HashMap<>();
        for (String propertyName : propertyNames) {
            if (propertyName != null && ENROLL_USER_IN_FLOW_CONFIG.equals(propertyName)) {
                defaultValues.put(propertyName, "true");
            }
        }
        return defaultValues;
    }
}
