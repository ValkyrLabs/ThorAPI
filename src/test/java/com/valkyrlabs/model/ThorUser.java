package com.valkyrlabs.model;

import java.util.UUID;

/**
 * Minimal test stub for ThorUser to exercise self-check logic in
 * ValkyrAIPermissionEvaluator.
 */
public class ThorUser {
  private final UUID id;

	private UUID ownerId = null;

	public void setOwnerId(UUID oid){
		this.ownerId = oid;
	}
	
  public ThorUser(UUID id) {
    this.id = id;
  }

  public UUID getId() {
    return id;
  }
}

