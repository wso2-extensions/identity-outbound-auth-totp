/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.totp.TOTPAuthenticatorConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

/**
 * TOTP Authenticator Implementation.
 *
 * @since 2.0.3
 */
public final class TOTPAuthenticatorCredentials {
	/**
	 * The system property to specify the random number generator algorithm to use.
	 */
	public static final String RNG_ALGORITHM = "com.wso2.rng.algorithm";

	/**
	 * The system property to specify the random number generator provider to use.
	 */
	public static final String RNG_ALGORITHM_PROVIDER = "com.wso2.rng.algorithmProvider";

	/**
	 * The logger for this class.
	 */
	private static final Logger LOGGER =
			Logger.getLogger(TOTPAuthenticatorCredentials.class.getName());

	/**
	 * The number of bits of a secret key in binary form. Since the Base32
	 * encoding with 8 bit characters introduces an 160% overhead, we just need
	 * 80 bits (10 bytes) to generate a 16 bytes Base32-encoded secret key.
	 */
	private static final int SECRET_BITS = 80;

	/**
	 * Number of scratch codes to generate during the key generation.
	 */
	private static final int SCRATCH_CODES = 5;

	/**
	 * Number of digits of a scratch code represented as a decimal integer.
	 */
	private static final int SCRATCH_CODE_LENGTH = 8;

	/**
	 * Length in bytes of each scratch code.
	 */
	private static final int BYTES_PER_SCRATCH_CODE = 4;

	/**
	 * The default SecureRandom algorithm to use if none is specified.
	 *
	 * @see java.security.SecureRandom#getInstance(String)
	 */
	private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

	/**
	 * The default random number algorithm provider to use if none is specified.
	 *
	 * @see java.security.SecureRandom#getInstance(String)
	 */
	private static final String DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";

	/**
	 * Cryptographic hash function used to calculate the HMAC (Hash-based
	 * Message Authentication Code). This implementation uses the SHA1 hash
	 * function.
	 */
	private static final String HMAC_HASH_FUNCTION = "HmacSHA1";

	/**
	 * The configuration used by the current instance.
	 */
	private final TOTPAuthenticatorConfig config;

	/**
	 * The internal SecureRandom instance used by this class.  Since Java 7
	 * {@link Random} instances are required to be thread-safe, no synchronisation is
	 * required in the methods of this class using this instance.  Thread-safety
	 * of this class was a de-facto standard in previous versions of Java so
	 * that it is expected to work correctly in previous versions of the Java
	 * platform as well.
	 */
	private TOTPReseedingSecureRandom secureRandom =
			new TOTPReseedingSecureRandom(getRandomNumberAlgorithm(),
			                              getRandomNumberAlgorithmProvider());

	public TOTPAuthenticatorCredentials(TOTPAuthenticatorConfig config) {
		if (config == null) {
			throw new TOTPAuthenticatorException("Configuration cannot be null.");
		}
		this.config = config;
	}

	/**
	 * Get random number generator algorithm.
	 *
	 * @return the random number generator algorithm
	 */
	private String getRandomNumberAlgorithm() {
		return System.getProperty(RNG_ALGORITHM, DEFAULT_RANDOM_NUMBER_ALGORITHM);
	}

	/**
	 * Get random number generator algorithm provider.
	 *
	 * @return the random number generator algorithm provider
	 */
	private String getRandomNumberAlgorithmProvider() {
		return System.getProperty(RNG_ALGORITHM_PROVIDER, DEFAULT_RANDOM_NUMBER_ALGORITHM_PROVIDER);
	}

	/**
	 * Calculates the verification code of the provided key at the specified
	 * instant of time using the algorithm specified in RFC 6238.
	 *
	 * @param key the secret key in binary format
	 * @param tm  the instant of time
	 * @return the validation code for the provided key at the specified instant
	 * of time.
	 */
	private int calculateCode(byte[] key, long tm) {
		// Allocating an array of bytes to represent the specified instant
		// of time.
		byte[] data = new byte[8];
		long value = tm;

		// Converting the instant of time from the long representation to a
		// big-endian array of bytes (RFC4226, 5.2. Description).
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		// Building the secret key specification for the HmacSHA1 algorithm.
		SecretKeySpec signKey = new SecretKeySpec(key, HMAC_HASH_FUNCTION);

		try {
			// Getting an HmacSHA1 algorithm implementation from the Java Cryptography Extension(JCE).
			Mac mac = Mac.getInstance(HMAC_HASH_FUNCTION);

			// Initializing the MAC algorithm.
			mac.init(signKey);

			// Processing the instant of time and getting the encrypted data.
			byte[] hash = mac.doFinal(data);

			// Building the validation code performing dynamic truncation
			// (RFC4226, 5.3. Generating an HOTP value)
			int offset = hash[hash.length - 1] & 0xF;

			// We are using a long because Java hasn't got an unsigned integer type
			// and we need 32 unsigned bits).
			long truncatedHash = 0;

			for (int i = 0; i < 4; ++i) {
				truncatedHash <<= 8;

				// Java bytes are signed but we need an unsigned integer:
				// cleaning off all but the LSB.
				truncatedHash |= (hash[offset + i] & 0xFF);
			}

			// Clean bits higher than the 32nd (inclusive) and calculate the
			// module with the maximum validation code value.
			truncatedHash &= 0x7FFFFFFF;
			truncatedHash %= config.getKeyModulus();

			// Returning the validation code to the caller.
			return (int) truncatedHash;
		} catch (NoSuchAlgorithmException e) {
			// We're not disclosing internal error details to our clients.
			throw new TOTPAuthenticatorException("Could not find algorithm to generate code", e);
		} catch (InvalidKeyException e) {
			throw new TOTPAuthenticatorException("Error while initializing the MAC algorithm.", e);
		}
	}

	/**
	 * Get time window form time.
	 *
	 * @param time time in millisecond
	 * @return time window form time
	 */
	private long getTimeWindowFromTime(long time) {
		return time / this.config.getTimeStepSizeInMillis();
	}

	/**
	 * This method implements the algorithm specified in RFC 6238 to check if a validation code is
	 * valid in a given instant of time for the given secret key.
	 *
	 * @param secret    The Base32 encoded secret key
	 * @param code      The code to validate
	 * @param timestamp The instant of time to use during the validation process
	 * @param window    The window size to use during the validation process
	 * @return <code>true</code> if the validation code is valid, <code>false</code> otherwise
	 */
	private boolean checkCode(byte[] secret, long code, long timestamp, int window) {
		byte[] decodedKey = decodeSecret(secret);

		// convert unix time into a 30 second "window" as specified by the TOTP specification.
		// Using default interval of 30 seconds.
		final long timeWindow = getTimeWindowFromTime(timestamp);

		// Calculating the verification code of the given key in each of the
		// time intervals and returning true if the provided code is equal to
		// one of them.
		for (int i = -((window - 1) / 2); i <= window / 2; ++i) {
			// Calculating the verification code for the current time interval.
			long hash = calculateCode(decodedKey, timeWindow + i);

			// Checking if the provided code is equal to the calculated one.
			if (hash == code) {
				// The verification code is valid.
				return true;
			}
		}
		// The verification code is invalid.
		return false;
	}

	/**
	 * Decode the secret key.
	 *
	 * @param secret Secret key
	 * @return Decoded secret key
	 */
	private byte[] decodeSecret(byte[] secret) {
		// Decoding the secret key to get its raw byte representation.
		switch (config.getKeyRepresentation()) {
			case BASE32:
				Base32 codec32 = new Base32();
				return codec32.decode(secret);
			case BASE64:
				Base64 codec64 = new Base64();
				return codec64.decode(secret);
			default:
				throw new TOTPAuthenticatorException("Unknown key representation type.");
		}
	}

	/**
	 * Generate the credential.
	 *
	 * @return credential
	 */
	public TOTPAuthenticatorKey createCredentials() {

		// Allocating a buffer sufficiently large to hold the bytes required by
		// the secret key and the scratch codes.
		byte[] buffer = new byte[SECRET_BITS / 8 + SCRATCH_CODES * BYTES_PER_SCRATCH_CODE];

		secureRandom.nextBytes(buffer);

		// Extracting the bytes making up the secret key.
		byte[] secretKey = Arrays.copyOf(buffer, SECRET_BITS / 8);
		String generatedKey = calculateSecretKey(secretKey);

		// Generating the verification code at time = 0.
		int validationCode = calculateValidationCode(secretKey);

		return new TOTPAuthenticatorKey(generatedKey, validationCode);
	}

	/**
	 * This method calculates the validation code at time 0.
	 *
	 * @param secretKey The secret key to use.
	 * @return the validation code at time 0.
	 */
	private int calculateValidationCode(byte[] secretKey) {
		return calculateCode(secretKey, 0);
	}

	/**
	 * This method calculates the secret key given a random byte buffer.
	 *
	 * @param secretKey A random byte buffer
	 * @return The secret key
	 */
	private String calculateSecretKey(byte[] secretKey) {
		switch (config.getKeyRepresentation()) {
			case BASE32:
				return new Base32().encodeToString(secretKey);
			case BASE64:
				return new Base64().encodeToString(secretKey);
			default:
				throw new TOTPAuthenticatorException("Unknown key representation type.");
		}
	}

	/**
	 * Authorize the code belongs to secret key.
	 *
	 * @param secretKey        The Secret Key
	 * @param verificationCode Verification code which needs to be verified
	 * @return true, if code is verified
	 */
	@Deprecated
	public boolean authorize(String secretKey, int verificationCode) {
		return authorize(secretKey.getBytes(), verificationCode, new Date().getTime());
	}

	/**
	 * Authorize the code belongs to secret key.
	 *
	 * @param secretKey        The byte array of the Secret Key.
	 * @param verificationCode Verification code which needs to be verified.
	 * @return true, if code is verified.
	 */
	public boolean authorize(byte[] secretKey, int verificationCode) {

		return authorize(secretKey, verificationCode, new Date().getTime());
	}

	/**
	 * Check whether the verification code is valid.
	 *
	 * @param verificationCode Verification code.
	 * @param username         Username.
	 * @return whether the verification code is valid or not.
	 */
	public boolean isValidVerificationCode(int verificationCode, String username) {

		byte[] secretKey = new byte[0];
		String tenantAwareUsername = null;
		try {
			UserRealm userRealm = TOTPUtil.getUserRealm(username);
			if (userRealm != null) {
				tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
				Map<String, String> userClaimValues = userRealm.getUserStoreManager().
						getUserClaimValues(tenantAwareUsername,
								new String[]{TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL}, null);
				secretKey = TOTPUtil.decryptSecret(userClaimValues.
						get(TOTPAuthenticatorConstants.VERIFY_SECRET_KEY_CLAIM_URL));
				if (authorize(secretKey, verificationCode, new Date().getTime())) {
					storeSecretKey(secretKey, username);
					return true;
				}
			}
			return false;
		} catch (UserStoreException e) {
			throw new TOTPAuthenticatorException("Verification code validation failed while trying to access user " +
					"store manager for the user : " + tenantAwareUsername, e);
		} catch (AuthenticationFailedException e) {
			throw new TOTPAuthenticatorException("Verification code validation cannot get the user " +
					"realm for the user: " + tenantAwareUsername, e);
		} catch (CryptoException e) {
			throw new TOTPAuthenticatorException("Verification code validation failed while decrypt the " +
					"stored SecretKey ", e);
		}
	}

	private void storeSecretKey(byte[] secretKey, String username) {

		Map<String, String> userClaims = new HashMap<>();
		String tenantAwareUsername = null;
		try {
			UserRealm userRealm = TOTPUtil.getUserRealm(username);
			if (userRealm != null) {
				userClaims.put(TOTPAuthenticatorConstants.SECRET_KEY_CLAIM_URL, TOTPUtil.encrypt(secretKey));
				tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
				userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, userClaims, null);
			}
		} catch (UserStoreException e) {
			throw new TOTPAuthenticatorException("TOTPKeyGenerator failed while trying to access user store manager " +
					"for the user : " + tenantAwareUsername, e);
		} catch (AuthenticationFailedException e) {
			throw new TOTPAuthenticatorException("TOTPKeyGenerator cannot get the user realm for the user", e);
		} catch (CryptoException e) {
			throw new TOTPAuthenticatorException("TOTPAdminService failed while decrypt the stored SecretKey ", e);
		}
	}

	/**
	 * Authorize the verification code belongs to secret key and time.
	 *
	 * @param secretKey        The secret key
	 * @param verificationCode The verification code which needs to be verified
	 * @param time             The time in milliseconds
	 * @return true, if validation code is verified
	 */
	private boolean authorize(byte[] secretKey, int verificationCode, long time) {
		// Checking user input and failing if the secret key was not provided.
		if (secretKey == null) {
			throw new IllegalArgumentException("Secret key cannot be null.");
		}
		// Checking if the verification code is between the legal bounds.
		if (verificationCode <= 0 || verificationCode >= this.config.getKeyModulus()) {
			return false;
		}
		// Checking the validation code using the current UNIX time.
		return checkCode(secretKey, verificationCode, time, this.config.getWindowSize());
	}
}