package com.valkyrlabs.thorapi.config.impl;

import java.util.UUID;

import org.openapitools.jackson.nullable.JsonNullable;
import org.springframework.security.acls.model.Sid;

/**
 * Adapter class to wrap a UUID or String as a Sid.
 * 
 * NOTE: This exists only because the generated AclSid model is not always used
 * directly as a Sid. If/when the model is updated and used directly, this class
 * should be removed and replaced with direct usage of AclSid or PrincipalSid.
 */
public class SidAdapter implements Sid {

  private static final long serialVersionUID = 1L;

  private UUID sid = null;
  private String sidString = null;

  public SidAdapter(String _sid) {
    this.sidString = _sid;
  }

  public SidAdapter(UUID _sid) {
    this.sid = _sid;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof SidAdapter))
      return false;
    SidAdapter other = (SidAdapter) obj;
    if (sid != null && other.sid != null) {
      return sid.equals(other.sid);
    } else if (sidString != null && other.sidString != null) {
      return sidString.equals(other.sidString);
    }
    return false;
  }

  @Override
  public String toString() {
    if (sid != null) {
      return sid.toString();
    } else if (sidString != null) {
      return sidString;
    } else {
      return "anonymous";
    }
  }

  @Override
  public int hashCode() {
    if (sid != null) {
      return sid.hashCode();
    } else if (sidString != null) {
      return sidString.hashCode();
    } else {
      return 0;
    }
  }
}
