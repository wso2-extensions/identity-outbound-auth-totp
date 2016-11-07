/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.totp.util;

import java.util.concurrent.TimeUnit;

/**
 * TOTP Authenticator config
 *
 * @since 2.0.2
 */
public class TOTPAuthenticatorConfig {
    private long timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30);
    private int windowSize = 3;
    private int codeDigits = 6;
    private int keyModulus = (int) Math.pow(10, codeDigits);
    private TOTPKeyRepresentation keyRepresentation = TOTPKeyRepresentation.BASE32;

    /**
     * Returns the key module.
     *
     * @return the key module.
     */
    public int getKeyModulus() {
        return keyModulus;
    }

    /**
     * Returns the key representation.
     *
     * @return the key representation.
     */
    public TOTPKeyRepresentation getKeyRepresentation() {
        return keyRepresentation;
    }

    /**
     * Returns the number of digits in the generated code.
     *
     * @return the number of digits in the generated code.
     */
    @SuppressWarnings("UnusedDeclaration")
    public int getCodeDigits() {
        return codeDigits;
    }

    /**
     * Returns the time step size, in milliseconds, as specified by RFC 6238.
     * The default value is 30.000.
     *
     * @return the time step size in milliseconds.
     */
    public long getTimeStepSizeInMillis() {
        return timeStepSizeInMillis;
    }

    /**
     * Returns an integer value representing the number of windows of size
     * timeStepSizeInMillis that are checked during the validation process,
     * to account for differences between the server and the client clocks.
     * The bigger the window, the more tolerant the library code is about
     * clock skews.
     *
     * @return the window size.
     * @see #timeStepSizeInMillis
     */
    public int getWindowSize() {
        return windowSize;
    }

    /**
     * TOTPAuthenticator Configuration builder
     */
    public static class TOTPAuthenticatorConfigBuilder {
        private TOTPAuthenticatorConfig config = new TOTPAuthenticatorConfig();

        /**
         * returns the TOTPAuthenticatorConfig instance
         *
         * @return config
         */
        public TOTPAuthenticatorConfig build() {
            return config;
        }

        /**
         * Set the number of digits in the generated code.
         *
         * @param codeDigits the codeDigits
         * @return this codeDigits
         */
        public TOTPAuthenticatorConfigBuilder setCodeDigits(int codeDigits) {
            if (codeDigits <= 0) {
                throw new IllegalArgumentException("Code digits must be positive.");
            }

            if (codeDigits < 6) {
                throw new IllegalArgumentException("The minimum number of digits is 6.");
            }

            if (codeDigits > 8) {
                throw new IllegalArgumentException("The maximum number of digits is 8.");
            }
            config.codeDigits = codeDigits;
            config.keyModulus = (int) Math.pow(10, codeDigits);
            return this;
        }

        /**
         * Set the time step size, in milliseconds, as specified by RFC 6238.
         *
         * @param timeStepSizeInMillis the timeStepSizeInMillis
         * @return this timeStepSizeInMillis
         */
        public TOTPAuthenticatorConfigBuilder setTimeStepSizeInMillis(long timeStepSizeInMillis) {
            if (timeStepSizeInMillis <= 0) {
                throw new IllegalArgumentException("Time step size must be positive.");
            }
            config.timeStepSizeInMillis = timeStepSizeInMillis;
            return this;
        }

        /**
         * Set an integer value representing the number of windows of size
         *
         * @param windowSize the windowSize
         * @return this windowSize
         */
        public TOTPAuthenticatorConfigBuilder setWindowSize(int windowSize) {
            if (windowSize <= 0) {
                throw new IllegalArgumentException("Window number must be positive.");
            }
            config.windowSize = windowSize;
            return this;
        }

        /**
         * Set the key representation.
         *
         * @param keyRepresentation the keyRepresentation
         * @return this keyRepresentation
         */
        public TOTPAuthenticatorConfigBuilder setKeyRepresentation(TOTPKeyRepresentation keyRepresentation) {
            if (keyRepresentation == null) {
                throw new IllegalArgumentException("Key representation cannot be null.");
            }
            config.keyRepresentation = keyRepresentation;
            return this;
        }
    }
}