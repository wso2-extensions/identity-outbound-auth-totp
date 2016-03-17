/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.totp;

public abstract class TOTPAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "TOTPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "totp";
    public static final String AUTHENTICATOR_STATUS = "TOTPAuthenticatorStatus";
    public static final String QR_CODE_CLAIM_URL = "http://wso2.org/claims/identity/qrcodeurl";
    public static final String SECRET_KEY_CLAIM_URL = "http://wso2.org/claims/identity/secretkey";
    public static final String ENCODING_CLAIM_URL = "http://wso2.org/claims/identity/encoding";
    public static final String BASE32 = "Base32";
    public static final String BASE64 = "Base64";
    public static final String SHA1 = "SHA-1";
    public static final String MD5 = "MD5";
    public static final long DEFAULT_TIME_STEP_SIZE = 30;
    public static final int DEFAULT_WINDOW_SIZE = 30;
    public static final String EMAIL_TEMPLATE_NMAME = "totp";
    public static final String AXIS2 = "axis2.xml";
    public static final String AXIS2_FILE = "repository/conf/axis2/axis2.xml";
    public static final String TRANSPORT_MAILTO = "mailto";
    public static final String EMAIL_CLAIM_URL = "http://wso2.org/claims/emailaddress";
}
