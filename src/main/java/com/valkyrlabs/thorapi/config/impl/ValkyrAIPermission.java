package com.valkyrlabs.thorapi.config.impl;

import org.springframework.security.acls.domain.AbstractPermission;
import org.springframework.security.acls.model.Permission;

/**
 * ValkyrAIPermission implements a custom permission scheme similar to Unix-like permissions.
 *
 * By utilizing these permissions effectively we can set it up so that an Agent that BUILDS automations
 * or creates content or objects that should be secured (ie: code is not alterable during execution time 
 * within the SecurityContext)
 * 
 * This should greatly enhance security, for example a workflow could have insert only access to transactional data 
 * while executing an operation involving untrusted 3rd party agents... 
 * 
 * Essentially we can build secure tools that we then send "low access" agents out into the world with, the 
 * tools can then be entrusted (signed definitely) and cryptographically secure, while the process itself lacks
 * any access t JWT or other authentication information including in memory (use SecureField on JWT for in-memory protection?)
 * 
 * <p>
 * This implementation extends AbstractPermission and uses bit masks to represent individual permissions.
 * Each permission is assigned a unique bit, which allows them to be combined via bitwise operations.
 * The permissions are grouped into three categories:
 * </p>
 *
 * <ul>
 *   <li>
 *     <b>Non-destructive:</b> These are safe operations that do not significantly alter system state.
 *     <ul>
 *       <li>{@code READ} (1): Allows reading or viewing data.</li>
 *       <li>{@code APPEND} (1 << 10, equals 1024): Allows adding new data while preventing overwrites.</li>
 *       <li>{@code INSERT} (1 << 1, equals 2): Permits inserting new data without modifying existing content.</li>
 *       <li>{@code CREATE} (1 << 2, equals 4): Grants permission to create new resources.</li>
 *       <li>{@code ENCRYPTION} (1 << 3, equals 8): Enables encryption-related operations.</li>
 *     </ul>
 *   </li>
 *
 *   <li>
 *     <b>Altering/destructive:</b> These operations change or remove existing data.
 *     <ul>
 *       <li>{@code WRITE} (1 << 4, equals 16): Allows modifying existing data.</li>
 *       <li>{@code DELETE} (1 << 5, equals 32): Permits removal of resources.</li>
 *     </ul>
 *   </li>
 *
 *   <li>
 *     <b>Danger zone:</b> These are high-risk operations that may affect system integrity or security.
 *     <ul>
 *       <li>{@code EXECUTE} (1 << 6, equals 64): Grants permission to execute actions or processes.</li>
 *       <li>{@code GRANTING} (1 << 7, equals 128): Allows the user to grant permissions to others.</li>
 *       <li>{@code ADMIN} (1 << 8, equals 256): Provides elevated administrative privileges.</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <p>
 * Adjust these bit masks if your design requires different values, but ensure that each permission occupies a distinct bit.
 * </p>
 */
public class ValkyrAIPermission extends AbstractPermission {

  private static final long serialVersionUID = 3242342342341L;

  /**
   * Default constructor initializing with a mask of 0 (no permissions).
   */
  protected ValkyrAIPermission() {
    super(0);
  }

  /**
   * Constructor that accepts a specific mask and a character code for display purposes.
   *
   * @param mask the bitmask representing the permission
   * @param code a character code representing the permission
   */
  protected ValkyrAIPermission(int mask, char code) {
    super(mask, code);
  }

  /**
   * Constructor that accepts a specific mask.
   *
   * @param mask the bitmask representing the permission
   */
  protected ValkyrAIPermission(int mask) {
    super(mask);
  }

  // ***********************
  // Non-destructive permissions:
  // These permissions enable operations that do not significantly alter system data.
  
  /**
   * READ permission (mask 1).
   * Allows reading or viewing data.
   */
  public static final Permission READ = new ValkyrAIPermission(1, 'R'); // 1 = 1 << 0

  /**
   * APPEND permission (mask 1 << 10, equals 1024).
   * Allows adding new records without modifying existing ones.
   */
  public static final Permission APPEND = new ValkyrAIPermission(1 << 10, 'P'); // 1024 = 1 << 10

  /**
   * INSERT permission (mask 1 << 1, equals 2).
   * Permits insertion of new data.
   */
  public static final Permission INSERT = new ValkyrAIPermission(1 << 1, 'I'); // 2 = 1 << 1

  /**
   * CREATE permission (mask 1 << 2, equals 4).
   * Grants permission to create new resources.
   */
  public static final Permission CREATE = new ValkyrAIPermission(1 << 2, 'C'); // 4 = 1 << 2

  /**
   * ENCRYPTION permission (mask 1 << 3, equals 8).
   * Enables operations related to encryption.
   */
  public static final Permission ENCRYPTION = new ValkyrAIPermission(1 << 3, 'E'); // 8 = 1 << 3

  // ***********************
  // Altering/destructive permissions:
  // These permissions allow operations that modify or remove existing data.
  
  /**
   * WRITE permission (mask 1 << 4, equals 16).
   * Permits modifying existing data.
   */
  public static final Permission WRITE = new ValkyrAIPermission(1 << 4, 'W'); // 16 = 1 << 4

  /**
   * DELETE permission (mask 1 << 5, equals 32).
   * Permits deletion of resources.
   */
  public static final Permission DELETE = new ValkyrAIPermission(1 << 5, 'D'); // 32 = 1 << 5

  // ***********************
  // Danger zone permissions:
  // These permissions are reserved for high-risk operations that require elevated privileges.
  
  /**
   * EXECUTE permission (mask 1 << 6, equals 64).
   * Allows execution of actions or processes.
   */
  public static final Permission EXECUTE = new ValkyrAIPermission(1 << 6, 'X'); // 64 = 1 << 6

  /**
   * GRANTING permission (mask 1 << 7, equals 128).
   * Permits granting of permissions to other users.
   */
  public static final Permission GRANTING = new ValkyrAIPermission(1 << 7, 'G'); // 128 = 1 << 7

  /**
   * ADMIN permission (mask 1 << 8, equals 256).
   * Provides elevated administrative privileges.
   */
  public static final Permission ADMIN = new ValkyrAIPermission(1 << 8, 'A'); // 256 = 1 << 8

  public static final Permission READ_WRITE_DELETE_PERMISSION = new ValkyrAIPermission(ValkyrAIPermission.WRITE.getMask()
  | ValkyrAIPermission.READ.getMask() | ValkyrAIPermission.DELETE.getMask(), 'O');

  // Field-level decryption view permission: allows returning decrypted values
  public static final Permission VIEW_DECRYPTED = new ValkyrAIPermission(1 << 9, 'V'); // 512 = 1 << 9



}
