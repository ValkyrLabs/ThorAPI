package com.valkyrlabs.thorapi.audit;

/* ##LICENSE## */

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
/**
 * Annotation to signal this field is an auto-generated auditing field
 *
 * @author John McMahon ~ github: SpaceGhost69 | twitter: @TechnoCharms
 * @see http://docs.valkyrlabs.com/docs/auditing/auditing-field.html
 */
public @interface AuditingField {

    boolean enabled() default true;

    public enum FieldType {

        AUDITED,
        
        SECURED,

        CREATED_BY,
        CREATED_DATE,

        LAST_ACCESSED_BY,
        LAST_ACCESSED_DATE,

        LAST_MODIFIED_BY,
        LAST_MODIFIED_DATE
    }

    /**
     * <p>fieldType.</p>
     *
     * @return a {@link com.valkyrlabs.thorapi.audit.AuditingField.FieldType} object
     */
    public FieldType fieldType() default FieldType.AUDITED;

}
