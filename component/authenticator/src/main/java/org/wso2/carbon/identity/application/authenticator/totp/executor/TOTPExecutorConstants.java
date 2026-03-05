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

/**
 * Constants for TOTP Executor.
 */
public class TOTPExecutorConstants {

    private TOTPExecutorConstants() {

    }

    public static final String TOKEN = "token";
    public static final String QR_CODE_URL = "qrCodeUrl";
    public static final String SECRET_KEY_CONTEXT_PROPERTY = "totpEnrollmentSecretKey";
    public static final String TOTP_AMR_VALUE = "totp";

    /**
     * Executor metadata key that controls whether TOTP enrollment is permitted in the flow
     * this executor is configured for. Set to "false" in the flow definition to restrict the
     * executor to authentication-only (token verification against an existing enrolled key).
     * Defaults to "true" when absent.
     */
    public static final String ALLOW_ENROLLMENT_METADATA_KEY = "allowEnrollment";

    /**
     * Context property key used to carry the resolved enrollment permission into execute().
     */
    public static final String ALLOW_ENROLLMENT_CONTEXT_KEY = "totpAllowEnrollment";
}
