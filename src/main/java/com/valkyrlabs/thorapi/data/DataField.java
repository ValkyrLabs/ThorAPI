package com.valkyrlabs.thorapi.data;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * <p>
 * DataField class.
 * </p>
 *
 * @author johnmcmahon
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface DataField {

    boolean unique() default false;

    boolean hidden() default false;

    boolean advanced() default false;

}
