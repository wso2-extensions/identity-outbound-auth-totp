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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

public class TOTPReseedingSecureRandom {
    private static final int MAX_OPERATIONS = 1_000_000;
    private final String provider;
    private final String algorithm;
    private final AtomicInteger count = new AtomicInteger(0);
    private SecureRandom secureRandom;

    @SuppressWarnings("UnusedDeclaration")
    TOTPReseedingSecureRandom() {
        this.algorithm = null;
        this.provider = null;
        buildSecureRandom();
    }

    @SuppressWarnings("UnusedDeclaration")
    TOTPReseedingSecureRandom(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        }

        this.algorithm = algorithm;
        this.provider = null;

        buildSecureRandom();
    }

    TOTPReseedingSecureRandom(String algorithm, String provider) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null.");
        }

        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null.");
        }

        this.algorithm = algorithm;
        this.provider = provider;

        buildSecureRandom();
    }

    private void buildSecureRandom() {
        try {
            if (this.algorithm == null && this.provider == null) {
                this.secureRandom = new SecureRandom();
            } else if (this.provider == null) {
                this.secureRandom = SecureRandom.getInstance(this.algorithm);
            } else {
                this.secureRandom = SecureRandom.getInstance(this.algorithm, this.provider);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new TOTPAuthenticatorException(
                    String.format("Could not initialise SecureRandom with the specified algorithm: %s. " +
                                    "Another provider can be chosen setting the %s system property.", this.algorithm,
                            TOTPAuthenticatorImpl.RNG_ALGORITHM), e);
        } catch (NoSuchProviderException e) {
            throw new TOTPAuthenticatorException(
                    String.format("Could not initialise SecureRandom with the specified provider: %s. " +
                                    "Another provider can be chosen setting the %s system property.", this.provider,
                            TOTPAuthenticatorImpl.RNG_ALGORITHM_PROVIDER), e);
        }
    }

    void nextBytes(byte[] bytes) {
        if (count.incrementAndGet() > MAX_OPERATIONS) {
            synchronized (this) {
                if (count.get() > MAX_OPERATIONS) {
                    buildSecureRandom();
                    count.set(0);
                }
            }
        }
        this.secureRandom.nextBytes(bytes);
    }
}
