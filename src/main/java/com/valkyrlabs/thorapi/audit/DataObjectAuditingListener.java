package com.valkyrlabs.thorapi.audit;

import com.valkyrlabs.model.DataObject;
import com.valkyrlabs.thorapi.service.AuditorService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Component
public class DataObjectAuditingListener {

    @Autowired
	private AuditorService auditorService; //  = new AuditorService();

    /** Constant <code>logger</code> */
    public static final Logger logger = LoggerFactory.getLogger(DataObjectAuditingListener.class);

    @PrePersist
    public void onCreate(Object entity) {
        if (!(entity instanceof DataObject data))
         return;
        
        Optional<UUID> maybeUser = auditorService.getCurrentAuditor();
        logger.trace("DATAOBJECT CREATED:{} | {} | userExists: {}", data.getClass().getName(), data.getId(), !maybeUser.isEmpty());
        if (maybeUser.isEmpty()){
            return;
        } 

        UUID userId = maybeUser.get();
        OffsetDateTime now = OffsetDateTime.now();
        data.setOwnerId(userId);
        data.setCreatedDate(now);

        data.setLastModifiedById(userId);
        data.setLastModifiedDate(now);
    }

    @PreUpdate
    public void onUpdate(Object entity) {
        if (!(entity instanceof DataObject data)) return;
        
        Optional<UUID> maybeUser = auditorService.getCurrentAuditor();

        logger.trace("DATAOBJECT UPDATED:{} | {} | userExists: {}", data.getClass().getName(), data.getId(), !maybeUser.isEmpty());
        if (maybeUser.isEmpty()) return;

        UUID userId = maybeUser.get();
        OffsetDateTime now = OffsetDateTime.now();
        
        if(data.getOwnerId() == null){
            data.setOwnerId(userId);
        }
        if(data.getCreatedDate() == null){
            data.setCreatedDate(now);
        }

        data.setLastModifiedById(userId);
        data.setLastModifiedDate(now);
    }
}