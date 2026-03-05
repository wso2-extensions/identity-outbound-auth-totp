/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp.executor;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPKeyGenerator;
import org.wso2.carbon.identity.application.authenticator.totp.exception.TOTPException;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorCredentials;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPAuthenticatorKey;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPKeyRepresentation;
import org.wso2.carbon.identity.application.authenticator.totp.util.TOTPUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * TOTP Executor for handling TOTP enrollment and authentication within any flow.
 *
 * The executor determines at runtime whether to enroll or authenticate by checking
 * whether the user already has a TOTP secret key stored. This makes it flow-agnostic:
 * it works for initial registration, progressive enrollment in password recovery, or
 * straight TOTP verification in any flow type.
 */
public class TOTPExecutor extends AuthenticationExecutor {

    private static final Log log = LogFactory.getLog(TOTPExecutor.class);

    @Override
    public String getName() {

        return "TOTPExecutor";
    }

    @Override
    public String getAMRValue() {

        return TOTPExecutorConstants.TOTP_AMR_VALUE;
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    /**
     * Reads the {@code allowEnrollment} metadata entry from the executor's flow configuration
     * and parks the resolved value into the context so that {@link #execute} can use it without
     * needing to re-read the DTO. Defaults to {@code true} when the key is absent, preserving
     * backward-compatible behaviour for flows that do not explicitly configure this setting.
     */
    @Override
    public void addIdpConfigsToContext(FlowExecutionContext context, ExecutorDTO executorDTO)
            throws FlowEngineServerException {

        super.addIdpConfigsToContext(context, executorDTO);

        boolean allowEnrollment = true;
        if (executorDTO != null && executorDTO.getMetadata() != null) {
            String value = executorDTO.getMetadata().get(TOTPExecutorConstants.ALLOW_ENROLLMENT_METADATA_KEY);
            if (value != null) {
                allowEnrollment = Boolean.parseBoolean(value);
            }
        }
        context.setProperty(TOTPExecutorConstants.ALLOW_ENROLLMENT_CONTEXT_KEY, allowEnrollment);
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        ExecutorResponse response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());

        String tokenInput = context.getUserInputData().get(TOTPExecutorConstants.TOKEN);

        if (StringUtils.isBlank(tokenInput)) {
            return initiateTotp(context, response);
        }
        return validateTotp(context, response, tokenInput);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        ExecutorResponse response = new ExecutorResponse();
        response.setContextProperty(new HashMap<>());

        // If this executor ran in enrollment mode, clear the TOTP claims that were set.
        if (isEnrollmentMode(context)) {
            Map<String, Object> clearClaims = new HashMap<>();
            clearClaims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, "");
            clearClaims.put(TOTPAuthenticatorConstants.TOTP_ENABLED_CLAIM_URI, "false");
            response.setUpdatedUserClaims(clearClaims);
        }
        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }

    /**
     * Determines whether to initiate enrollment or authentication based on whether the user
     * already has a TOTP secret key. If the user has no stored key (or cannot be found in the
     * user store yet, e.g. mid-registration), enrollment is initiated.
     */
    private ExecutorResponse initiateTotp(FlowExecutionContext context, ExecutorResponse response) {

        if (needsEnrollment(context)) {
            return initiateEnrollment(context, response);
        }
        // User already has TOTP enrolled — just prompt for the verification token.
        response.setResult(Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(TOTPExecutorConstants.TOKEN));
        return response;
    }

    private ExecutorResponse initiateEnrollment(FlowExecutionContext context, ExecutorResponse response) {

        String tenantDomain = context.getTenantDomain();
        try {
            TOTPAuthenticatorKey totpKey = TOTPKeyGenerator.generateKey(tenantDomain);
            String secretKey = totpKey.getKey();

            // Store the encoded secret key in context — its presence signals enrollment mode.
            response.getContextProperties().put(TOTPExecutorConstants.SECRET_KEY_CONTEXT_PROPERTY, secretKey);

            String qrCodeUrl = buildQRCodeUrl(context, secretKey);
            Map<String, String> additionalInfo = new HashMap<>();
            additionalInfo.put(TOTPExecutorConstants.QR_CODE_URL, qrCodeUrl);
            response.setAdditionalInfo(additionalInfo);

        } catch (AuthenticationFailedException | TOTPException e) {
            return errorResponse(response, "Error while generating TOTP enrollment key: " + e.getMessage());
        }

        response.setResult(Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        response.setRequiredData(Arrays.asList(TOTPExecutorConstants.TOKEN));
        return response;
    }

    private ExecutorResponse validateTotp(FlowExecutionContext context, ExecutorResponse response,
                                          String tokenInput) {

        int token;
        try {
            token = Integer.parseInt(tokenInput.trim());
        } catch (NumberFormatException e) {
            return retryResponse(response, "Invalid TOTP token format.");
        }

        // Presence of a context-stored secret key means we are in enrollment mode.
        if (isEnrollmentMode(context)) {
            return validateEnrollmentToken(context, response, token);
        }
        return validateAuthenticationToken(context, response, token);
    }

    private ExecutorResponse validateEnrollmentToken(FlowExecutionContext context, ExecutorResponse response,
                                                     int token) {

        String secretKey = (String) context.getProperty(TOTPExecutorConstants.SECRET_KEY_CONTEXT_PROPERTY);
        if (StringUtils.isBlank(secretKey)) {
            return errorResponse(response, "TOTP secret key not found in context. Please restart the enrollment.");
        }

        String tenantDomain = context.getTenantDomain();
        TOTPAuthenticatorCredentials totpAuthenticator = buildTotpAuthenticator(tenantDomain);

        if (!totpAuthenticator.authorize(secretKey, token)) {
            return retryResponse(response, "Invalid TOTP token. Please verify the code from your authenticator app.");
        }

        try {
            Map<String, Object> updatedClaims = new HashMap<>();
            updatedClaims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL,
                    TOTPUtil.getProcessedClaimValue(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, secretKey,
                            tenantDomain));
            updatedClaims.put(TOTPAuthenticatorConstants.TOTP_ENABLED_CLAIM_URI, "true");
            response.setUpdatedUserClaims(updatedClaims);
        } catch (Exception e) {
            return errorResponse(response, "Error while storing TOTP enrollment data: " + e.getMessage());
        }

        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }

    private ExecutorResponse validateAuthenticationToken(FlowExecutionContext context, ExecutorResponse response,
                                                         int token) {

        String username = context.getFlowUser().getUsername();
        String tenantDomain = context.getTenantDomain();
        String fullUsername = UserCoreUtil.addTenantDomainToEntry(username, tenantDomain);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(fullUsername);

        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(fullUsername);
            if (userRealm == null) {
                return errorResponse(response, "Unable to load user realm for tenant: " + tenantDomain);
            }

            Map<String, String> userClaims = userRealm.getUserStoreManager().getUserClaimValues(
                    tenantAwareUsername,
                    new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL},
                    null);

            String encryptedSecretKey = userClaims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL);
            if (StringUtils.isBlank(encryptedSecretKey)) {
                return errorResponse(response, "TOTP is not enrolled for the user.");
            }

            String secretKey = TOTPUtil.decrypt(encryptedSecretKey);
            TOTPAuthenticatorCredentials totpAuthenticator = buildTotpAuthenticator(tenantDomain);

            if (!totpAuthenticator.authorize(secretKey, token)) {
                return retryResponse(response, "Invalid TOTP token.");
            }

        } catch (UserStoreException e) {
            return errorResponse(response, "Error accessing user store: " + e.getMessage());
        } catch (AuthenticationFailedException e) {
            return errorResponse(response, "Error loading user realm: " + e.getMessage());
        } catch (CryptoException e) {
            return errorResponse(response, "Error decrypting TOTP secret key: " + e.getMessage());
        }

        response.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
        return response;
    }

    /**
     * Checks whether the user needs TOTP enrollment. Returns false immediately when the flow
     * configuration has explicitly disabled enrollment (allowEnrollment=false), so the executor
     * will only ever verify an existing TOTP key in that flow. Otherwise checks the user store:
     * returns true when the user has no key stored, including when the user does not exist yet
     * (e.g. mid-registration).
     */
    private boolean needsEnrollment(FlowExecutionContext context) {

        Object allowEnrollmentProp = context.getProperty(TOTPExecutorConstants.ALLOW_ENROLLMENT_CONTEXT_KEY);
        if (allowEnrollmentProp instanceof Boolean && !(Boolean) allowEnrollmentProp) {
            return false;
        }

        String username = context.getFlowUser().getUsername();
        if (StringUtils.isBlank(username)) {
            return true;
        }

        String tenantDomain = context.getTenantDomain();
        String fullUsername = UserCoreUtil.addTenantDomainToEntry(username, tenantDomain);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(fullUsername);

        try {
            UserRealm userRealm = TOTPUtil.getUserRealm(fullUsername);
            if (userRealm == null) {
                return true;
            }
            Map<String, String> claims = userRealm.getUserStoreManager().getUserClaimValues(
                    tenantAwareUsername,
                    new String[]{TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL},
                    null);
            return StringUtils.isBlank(claims.get(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL));
        } catch (UserStoreException | AuthenticationFailedException e) {
            // User does not exist in the store yet (e.g. mid-registration) or store is
            // unavailable — treat as needing enrollment.
            if (log.isDebugEnabled()) {
                log.debug("Could not retrieve TOTP secret key for user: " + tenantAwareUsername
                        + ". Treating as enrollment required.", e);
            }
            return true;
        }
    }

    /**
     * Returns true when a generated secret key has been stored in the flow context, indicating
     * that enrollment was initiated for this execution.
     */
    private boolean isEnrollmentMode(FlowExecutionContext context) {

        return StringUtils.isNotBlank(
                (String) context.getProperty(TOTPExecutorConstants.SECRET_KEY_CONTEXT_PROPERTY));
    }

    private String buildQRCodeUrl(FlowExecutionContext context, String secretKey)
            throws TOTPException, AuthenticationFailedException {

        String tenantDomain = context.getTenantDomain();
        String username = context.getFlowUser().getUsername();
        String issuer = TOTPUtil.getTOTPIssuerDisplayName(tenantDomain, null);
        long timeStep = TOTPUtil.getTimeStepSize(tenantDomain);

        String qrCodeUri = "otpauth://totp/" + issuer + ":"
                + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "?secret=" + secretKey + "&issuer=" + issuer + "&period=" + timeStep;

        return Base64.encodeBase64String(qrCodeUri.getBytes(StandardCharsets.UTF_8));
    }

    private TOTPAuthenticatorCredentials buildTotpAuthenticator(String tenantDomain) {

        TOTPKeyRepresentation encoding = TOTPKeyRepresentation.BASE32;
        try {
            if (TOTPAuthenticatorConstants.BASE64.equals(TOTPUtil.getEncodingMethod(tenantDomain))) {
                encoding = TOTPKeyRepresentation.BASE64;
            }
        } catch (AuthenticationFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not determine encoding method for tenant: " + tenantDomain
                        + ". Defaulting to BASE32.", e);
            }
        }

        long timeStep;
        try {
            timeStep = TimeUnit.SECONDS.toMillis(TOTPUtil.getTimeStepSize(tenantDomain));
        } catch (AuthenticationFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not determine time step size for tenant: " + tenantDomain
                        + ". Using default 30 seconds.", e);
            }
            timeStep = TimeUnit.SECONDS.toMillis(30);
        }

        int windowSize;
        try {
            windowSize = TOTPUtil.getWindowSize(tenantDomain);
        } catch (AuthenticationFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not determine window size for tenant: " + tenantDomain
                        + ". Using default of 3.", e);
            }
            windowSize = 3;
        }

        TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder configBuilder =
                new TOTPAuthenticatorConfig.TOTPAuthenticatorConfigBuilder()
                        .setKeyRepresentation(encoding)
                        .setWindowSize(windowSize)
                        .setTimeStepSizeInMillis(timeStep);
        return new TOTPAuthenticatorCredentials(configBuilder.build());
    }

    private ExecutorResponse retryResponse(ExecutorResponse response, String message) {

        response.setResult(Constants.ExecutorStatus.STATUS_RETRY);
        response.setErrorMessage(message);
        response.setRequiredData(Arrays.asList(TOTPExecutorConstants.TOKEN));
        return response;
    }

    private ExecutorResponse errorResponse(ExecutorResponse response, String message) {

        response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
        response.setErrorMessage(message);
        return response;
    }
}
