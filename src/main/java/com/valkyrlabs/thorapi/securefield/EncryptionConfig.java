package com.valkyrlabs.thorapi.securefield;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>EncryptionConfig class.</p>
 *
 * @author johnmcmahon
 */
public class EncryptionConfig {

	/** Constant <code>logger</code> */
	protected static final Logger logger = LoggerFactory
			.getLogger(EncryptionConfig.class);

    static final String SECURE_KEY_PROPERTY = "THORAPI_SECRET_KEY";
    /**
     * Prefer environment variable; fall back to system property for tests.
     */
    protected static final String SECRET_KEY =
            System.getenv(SECURE_KEY_PROPERTY) != null ? System.getenv(SECURE_KEY_PROPERTY)
                    : System.getProperty(SECURE_KEY_PROPERTY);
	
	/** Constant <code>CIPHER_NAME="AES/GCM/NoPadding"</code> */
	public static final String CIPHER_NAME = "AES/GCM/NoPadding";
	static final String S3_VALKYR_MEDIA_FOLDER = null;
	static final Integer ANON_USERID = null;
	static final int KEY_SIZE = 256;
	static final String KEYGEN_INSTANCE_NAME = "AES";

}
