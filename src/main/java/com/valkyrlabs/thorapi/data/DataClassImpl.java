package com.valkyrlabs.thorapi.data;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

/**
 * base implementation for convenience
 *
 * @author johnmcmahon
 */
@Entity
public class DataClassImpl implements DataClass {

    @Id
    private UUID id;
    private UUID ownerId;
    private UUID lastModifiedById;
    private String keyHash;
    private UUID lastAccessedById;
    private OffsetDateTime createdDate;
    private OffsetDateTime lastAccessedDate;
    private OffsetDateTime lastModifiedDate;

    /** {@inheritDoc} */
    @Override
    public UUID getId() {
        return id;
    }

    /** {@inheritDoc} */
    @Override
    public void setId(UUID id) {
        this.id = id;
    }

    /** {@inheritDoc} */
    @Override
    public UUID getOwnerId() {
        return ownerId;
    }

    /** {@inheritDoc} */
    @Override
    public void setOwnerId(UUID ownerId) {
        this.ownerId = ownerId;
    }

    /** {@inheritDoc} */
    @Override
    public UUID getLastModifiedById() {
        return lastModifiedById;
    }

    /** {@inheritDoc} */
    @Override
    public void setLastModifiedById(UUID lastModifiedById) {
        this.lastModifiedById = lastModifiedById;
    }

    /** {@inheritDoc} */
    @Override
    public String getKeyHash() {
        return keyHash;
    }

    /** {@inheritDoc} */
    @Override
    public void setKeyHash(String keyHash) {
        this.keyHash = keyHash;
    }

    /** {@inheritDoc} */
    @Override
    public UUID getLastAccessedById() {
        return lastAccessedById;
    }

    /** {@inheritDoc} */
    @Override
    public void setLastAccessedById(UUID lastAccessedById) {
        this.lastAccessedById = lastAccessedById;
    }

    /** {@inheritDoc} */
    @Override
    public OffsetDateTime getCreatedDate() {
        return createdDate;
    }

    /** {@inheritDoc} */
    @Override
    public void setCreatedDate(OffsetDateTime createdDate) {
        this.createdDate = createdDate;
    }

    /** {@inheritDoc} */
    @Override
    public OffsetDateTime getLastAccessedDate() {
        return lastAccessedDate;
    }

    /** {@inheritDoc} */
    @Override
    public void setLastAccessedDate(OffsetDateTime lastAccessedDate) {
        this.lastAccessedDate = lastAccessedDate;
    }

    /** {@inheritDoc} */
    @Override
    public OffsetDateTime getLastModifiedDate() {
        return lastModifiedDate;
    }

    /** {@inheritDoc} */
    @Override
    public void setLastModifiedDate(OffsetDateTime lastModifiedDate) {
        this.lastModifiedDate = lastModifiedDate;
    }
}
