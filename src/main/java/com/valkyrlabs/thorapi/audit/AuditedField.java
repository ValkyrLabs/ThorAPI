package com.valkyrlabs.thorapi.audit;

/* ##LICENSE## */

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
/**
 * Annotation to signal this field is audited
 *
 * @author John McMahon ~ github: SpaceGhost69 | twitter: @TechnoCharms
 * @see http://docs.valkyrlabs.com/docs/auditing/auditing-field.html
 */
public @interface AuditedField {

    boolean enabled() default true;

    public enum FieldType {
        AUDITED,
        ENCRYPTED,
        SECURED
    }

    /**
     * <p>fieldType.</p>
     *
     * @return a {@link com.valkyrlabs.thorapi.audit.AuditedField.FieldType} object
     */
    public FieldType fieldType() default FieldType.AUDITED;

}
