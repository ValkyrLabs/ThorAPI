package com.valkyrlabs.thorapi.config.impl;

import java.io.Serializable;
import java.util.UUID;

import org.springframework.security.acls.model.ObjectIdentity;

import com.valkyrlabs.model.DataObject;

/**
 * <p>
 * ValkyrObjectIdentity class.
 * </p>
 *
 * @author johnmcmahon
 */
public class ValkyrObjectIdentity implements ObjectIdentity {

  /** Constant <code>serialVersionUID=0l</code> */
  public static final long serialVersionUID = 0l;

  private final transient Object identityObject;

  /**
   * <p>
   * Constructor for ValkyrObjectIdentity.
   * </p>
   *
   * @param objectIdentity a {@link java.lang.Object} object
   */
  public ValkyrObjectIdentity(Object objectIdentity) {
    identityObject = objectIdentity;
  }

  /** {@inheritDoc} */
  @Override
  public String getType() {
    return "VALKYR_OBJECT";
  }

  /** {@inheritDoc} */
  @Override
  public Serializable getIdentifier() {
    if(identityObject instanceof DataObject){
      return ((DataObject)identityObject).getId();
    }
    throw new UnsupportedOperationException("getIdentifier can only work with DataObject classes. Attempted to use on:" + identityObject.getClass().getName());
  }
}
