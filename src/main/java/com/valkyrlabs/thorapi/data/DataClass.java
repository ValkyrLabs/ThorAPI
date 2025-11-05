package com.valkyrlabs.thorapi.data;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

/**
 * these classes have the auto-generated sfields so we can use this to access the
 * values
 *
 * @author johnmcmahon
 */
@Entity
public interface DataClass extends Serializable {

    /**
     * <p>getId.</p>
     *
     * @return a {@link java.util.UUID} object
     */
    @Id
    UUID getId();
    /**
     * <p>setId.</p>
     *
     * @param id a {@link java.util.UUID} object
     */
    void setId(UUID id);

    /**
     * <p>getOwnerId.</p>
     *
     * @return a {@link java.util.UUID} object
     */
    UUID getOwnerId();
    /**
     * <p>setOwnerId.</p>
     *
     * @param ownerId a {@link java.util.UUID} object
     */
    void setOwnerId(UUID ownerId);

    /**
     * <p>getLastModifiedById.</p>
     *
     * @return a {@link java.util.UUID} object
     */
    UUID getLastModifiedById();
    /**
     * <p>setLastModifiedById.</p>
     *
     * @param u a {@link java.util.UUID} object
     */
    void setLastModifiedById(UUID u);

    /**
     * <p>getKeyHash.</p>
     *
     * @return a {@link java.lang.String} object
     */
    String getKeyHash();
    /**
     * <p>setKeyHash.</p>
     *
     * @param keyHash a {@link java.lang.String} object
     */
    void setKeyHash(String keyHash);

    /**
     * <p>getLastAccessedById.</p>
     *
     * @return a {@link java.util.UUID} object
     */
    UUID getLastAccessedById();
    /**
     * <p>setLastAccessedById.</p>
     *
     * @param u a {@link java.util.UUID} object
     */
    void setLastAccessedById(UUID u);

    /**
     * <p>getCreatedDate.</p>
     *
     * @return a {@link java.time.OffsetDateTime} object
     */
    OffsetDateTime getCreatedDate();
    /**
     * <p>setCreatedDate.</p>
     *
     * @param dt a {@link java.time.OffsetDateTime} object
     */
    void setCreatedDate(OffsetDateTime dt);

    /**
     * <p>getLastAccessedDate.</p>
     *
     * @return a {@link java.time.OffsetDateTime} object
     */
    OffsetDateTime getLastAccessedDate();
    /**
     * <p>setLastAccessedDate.</p>
     *
     * @param dt a {@link java.time.OffsetDateTime} object
     */
    void setLastAccessedDate(OffsetDateTime dt);

    /**
     * <p>getLastModifiedDate.</p>
     *
     * @return a {@link java.time.OffsetDateTime} object
     */
    OffsetDateTime getLastModifiedDate();
    /**
     * <p>setLastModifiedDate.</p>
     *
     * @param dt a {@link java.time.OffsetDateTime} object
     */
    void setLastModifiedDate(OffsetDateTime dt);
}
