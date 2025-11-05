package com.valkyrlabs.thorapi.audit;

/* ##LICENSE## */

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
/**
 * Annotation to signal this class is audited
 *
 * @author John McMahon ~ github: SpaceGhost69 | twitter: @TechnoCharms
 * @see http://docs.valkyrlabs.com/docs/auditing/auditing-field.html
 */
public @interface AuditedClass {

    boolean enabled() default true;

}
