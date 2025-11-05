package com.valkyrlabs.thorapi.securefield;

import java.lang.reflect.Field;
import java.util.regex.Pattern;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * <p>
 * Abstract SecureFieldAspect class.
 * </p>
 *
 * @author johnmcmahon
 */
@Aspect
@Component
@Configurable
public abstract class SecureFieldAspect {

	static final Logger logger = LoggerFactory.getLogger(SecureFieldAspect.class);

	private static final String FIELD_GET = "get(@com.valkyrlabs.thorapi.securefield.SecureField * *)";
	private static final String FIELD_SET = "set(@com.valkyrlabs.thorapi.securefield.SecureField * *)";
	private static final Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");
	private static final boolean DISABLE_SECURE_FIELD_ASPECT = false;

	// TODO: implement configurable strength from SecureKey.cipherWorkCost
	/** Constant <code>passwordEncoder</code> */
	public static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	/** Mask returned for callers without VIEW_DECRYPTED permission. */
	public static final String MASKED_VALUE = "<ENCRYPTED_VALUE/>";

	@Autowired(required = false)
	private PermissionEvaluator permissionEvaluator;

	/**
	 * <p>
	 * get.
	 * </p>
	 *
	 * @param pjp a {@link org.aspectj.lang.ProceedingJoinPoint} object
	 * @return a {@link java.lang.Object} object
	 * @throws java.lang.Throwable if any.
	 */
	@Around(FIELD_GET)
	public Object get(ProceedingJoinPoint pjp) throws Throwable {
		logger.trace("Intercepted getter: {}", pjp.toLongString());
		Object targetObject = pjp.getThis();
		Field field;
		try {
			field = SecureEncrypter.getField(pjp.getThis(), pjp.getSignature().getName());
			SecureField annotation = field.getAnnotation(SecureField.class);
			// handle password field (do not try to decrypt!) - HASHED fields are
			// irreversible, always return raw value
			if (annotation != null && annotation.encryptionType() == SecureField.EncryptionType.HASHED) {
				logger.debug("HASHED field detected: {}, returning raw value without permission checks", field.getName());
				return pjp.proceed(); // Return raw BCrypt hash from database, no permission gating needed
			}
			getFieldAndValidate(pjp);
		} catch (EncryptionException e) {
			logger.warn("EncryptionException", e);
			return pjp.proceed();
		}
		Object fieldValue = getFieldValue(field, targetObject);
		if (fieldValue == null || fieldValue.toString().isEmpty()) {
			// CRITICAL DEFENSIVE CHECK: If this is a HASHED field, NEVER mask it - return
			// raw value
			SecureField annotation = field.getAnnotation(SecureField.class);
			if (annotation != null && annotation.encryptionType() == SecureField.EncryptionType.HASHED) {
				logger.warn("DEFENSIVE: HASHED password field {} is null/empty, returning raw value anyway", field.getName());
				return pjp.proceed(); // Return whatever is in DB, even if null
			}

			Authentication auth = SecurityContextHolder.getContext() != null
					? SecurityContextHolder.getContext().getAuthentication()
					: null;
			if (isAnonymous(auth)) {
				return MASKED_VALUE;
			}
			try {
				boolean allowed = permissionEvaluator == null
						|| permissionEvaluator.hasPermission(auth, targetObject, "VIEW_DECRYPTED");
				if (!allowed) {
					return MASKED_VALUE;
				}
			} catch (Exception ignore) {
				return MASKED_VALUE;
			}
			return pjp.proceed();
		}
		// Permission-gated decryption
		// DEFENSIVE: Double-check this isn't a HASHED field that somehow made it here
		SecureField annotationCheckAgain = field.getAnnotation(SecureField.class);
		if (annotationCheckAgain != null && annotationCheckAgain.encryptionType() == SecureField.EncryptionType.HASHED) {
			logger.error("DEFENSIVE: HASHED password field {} reached decryption logic! Returning raw value",
					field.getName());
			return pjp.proceed(); // Return the raw hash
		}

		try {
			Authentication auth = SecurityContextHolder.getContext() != null
					? SecurityContextHolder.getContext().getAuthentication()
					: null;
			if (isAnonymous(auth)) {
				return MASKED_VALUE;
			}
			// Default to allowing writes when no PermissionEvaluator is present.
			// Reading remains permission-gated in the getter.
			boolean allowed = (permissionEvaluator == null)
					|| permissionEvaluator.hasPermission(auth, targetObject, "VIEW_DECRYPTED");
			if (!allowed) {
				// Caller does not have decryption permission; return masked token
				return MASKED_VALUE;
			}
		} catch (Exception ex) {
			logger.warn("Permission check failed; returning masked value: {}", ex.getMessage());
			return MASKED_VALUE;
		}

		// decrypt the field (authorized)
		SecureEncrypter secureEncrypter = new SecureEncrypter();
		return secureEncrypter.decrypt(fieldValue.toString());
	}

	/**
	 * <p>
	 * getFieldAndValidate.
	 * </p>
	 *
	 * @param pjp a {@link org.aspectj.lang.ProceedingJoinPoint} object
	 * @return a {@link java.lang.reflect.Field} object
	 * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
	 */
	protected Field getFieldAndValidate(ProceedingJoinPoint pjp) throws EncryptionException {
		if (DISABLE_SECURE_FIELD_ASPECT) {
			throw new EncryptionException("Secure field aspect is disabled. Proceeding without interception.");
		}
		Field field = SecureEncrypter.getField(pjp.getThis(), pjp.getSignature().getName());
		if (field == null) {
			throw new EncryptionException("Could not get field and validate: field is null: " + pjp.toLongString());
		}

		SecureField annotation = field.getAnnotation(SecureField.class);
		if (annotation == null || !annotation.enabled()) {
			throw new EncryptionException("Could not get annotation for SecureField: " + pjp.toLongString());
		}
		if (!field.getType().equals(String.class)) {
			throw new EncryptionException("Cannot decrypt or encrypt a non-String failed. Unsupported field type:");
		}
		return field;
	}

	/**
	 * <p>
	 * set.
	 * </p>
	 *
	 * @param pjp a {@link org.aspectj.lang.ProceedingJoinPoint} object
	 * @return a {@link java.lang.Object} object
	 * @throws java.lang.Throwable if any.
	 */
	@Around(FIELD_SET)
	public Object set(ProceedingJoinPoint pjp) throws Throwable {
		logger.trace("Intercepted setter: {}", pjp.toLongString());

		Object targetObject = pjp.getThis();
		Field field;
		try {
			field = getFieldAndValidate(pjp);
		} catch (EncryptionException e) {
			logger.warn("EncryptionException", e);
			return pjp.proceed();
		}
		Object arg = pjp.getArgs()[0];
		if (arg == null) {
			return pjp.proceed();
		}
		SecureField annotation = field.getAnnotation(SecureField.class);
		String clearTextValue = (String) arg;
		String currentFieldValue = (String) getFieldValue(field, targetObject);

		// For encrypted (non-HASHED) fields, require VIEW_DECRYPTED to modify.
		if (annotation.encryptionType() != SecureField.EncryptionType.HASHED) {
			try {
				Authentication auth = SecurityContextHolder.getContext() != null
						? SecurityContextHolder.getContext().getAuthentication()
						: null;
				if (isAnonymous(auth)) {
					logger.warn("Blocked update to encrypted field without VIEW_DECRYPTED permission");
					return currentFieldValue;
				}
				boolean allowed = permissionEvaluator != null
						&& permissionEvaluator.hasPermission(auth, targetObject, "VIEW_DECRYPTED");
				if (!allowed) {
					// If UI sent placeholder token, treat as no-op to support partial updates
					if (MASKED_VALUE.equals(clearTextValue)) {
						logger.trace("Ignoring secure field set with masked placeholder (no VIEW_DECRYPTED)");
						return currentFieldValue; // leave ciphertext unchanged
					}
					// Otherwise, block modification to encrypted field without VIEW_DECRYPTED
					logger.warn("Blocked update to encrypted field without VIEW_DECRYPTED permission");
					return currentFieldValue; // no-op
				}
			} catch (Exception ex) {
				logger.warn("Permission check failed during set; ignoring update: {}", ex.getMessage());
				return currentFieldValue; // safest default: no change
			}
		}
		String encryptedValue;
		SecureEncrypter secureEncrypter = new SecureEncrypter();
		if (annotation.encryptionType() == SecureField.EncryptionType.HASHED) {
			if (BCRYPT_PATTERN.matcher(clearTextValue).matches() && !clearTextValue.equals(currentFieldValue)) {
				logger.trace("Overwriting a hashed value with a different hashed value.");
				encryptedValue = clearTextValue;
			} else {
				String encodedValue = passwordEncoder.encode(clearTextValue);
				// logger.warn("WRITING ENCODED VALUE: {} - {}", clearTextValue, encodedValue);
				encryptedValue = encodedValue;
			}
		} else {
			encryptedValue = secureEncrypter.encrypt(clearTextValue);
		}
		setFieldValue(field, targetObject, encryptedValue);
		return encryptedValue;
	}

	private static Object getFieldValue(Field field, Object target) throws IllegalAccessException {
		boolean accessible = field.canAccess(target);
		field.setAccessible(true);
		Object value = field.get(target);
		field.setAccessible(accessible);
		// logger.trace("Getting value from field {}:{}", field.getName(), value);
		return value;
	}

	private boolean isAnonymous(Authentication auth) {
		if (auth == null) {
			return true;
		}
		if (!auth.isAuthenticated()) {
			return true;
		}
		String name = auth.getName();
		if (name != null && "anonymousUser".equalsIgnoreCase(name)) {
			return true;
		}
		return auth.getAuthorities() != null && auth.getAuthorities().stream()
				.anyMatch(authority -> authority != null && "ROLE_ANONYMOUS".equalsIgnoreCase(authority.getAuthority()));
	}

	private void setFieldValue(Field field, Object target, Object value) throws IllegalAccessException {
		if (field == null) {
			throw new IllegalAccessException("Field is null on: " + target.toString());
		}
		boolean accessible = field.canAccess(target);
		field.setAccessible(true);
		field.set(target, value);
		// logger.trace("Set value to field {}:{}", field.getName(), value);
		field.setAccessible(accessible);
	}
}
