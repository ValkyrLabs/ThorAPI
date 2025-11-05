package com.valkyrlabs.thorapi;

import com.github.jknack.handlebars.Helper;
import com.github.jknack.handlebars.Options;

/**
 * Translate OpenAPI types to Database types
 *
 * @author johnmcmahon
 */
public class MapTypeHelper implements Helper<String> {

    /** Constant <code>DEFAULT_TYPE="VARCHAR(255)"</code> */
    public static final String DEFAULT_TYPE = "VARCHAR(255)";

    /** {@inheritDoc} */
    @Override
    public CharSequence apply(String type, Options options) {
        if (type == null) {

            return DEFAULT_TYPE;
        }
        switch (type) {

        case "array":

            return "BLOB";

        case "integer":
            return "INT";

        case "string":
            return DEFAULT_TYPE; // Consider dynamic handling of string length if necessary

        case "boolean":
            return "BOOLEAN";

        case "number":
            return "DECIMAL"; // Adjust for float vs double if necessary

        default:

            return DEFAULT_TYPE; // Default case or you might throw an error
        }
    }
}
