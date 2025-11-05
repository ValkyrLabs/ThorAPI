package com.valkyrlabs.thorapi;

import com.github.jknack.handlebars.Helper;
import com.github.jknack.handlebars.Options;

/**
 * Handlebars helper to convert names like "LlmDetails" or "ACLRole" to
 * kebab-case path segments: "llm-details", "acl-role".
 */
public class KebabCaseHelper implements Helper<Object> {

    @Override
    public CharSequence apply(Object context, Options options) {
        if (context == null) {
            return "";
        }
        String s = String.valueOf(context).trim();
        if (s.isEmpty()) return "";

        // Replace separators with hyphen
        s = s.replace('_', '-').replace(' ', '-');

        // Insert hyphen before uppercase letters that follow a lowercase or digit
        StringBuilder out = new StringBuilder();
        char prev = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (i > 0 && Character.isUpperCase(c) && (Character.isLowerCase(prev) || Character.isDigit(prev))) {
                out.append('-');
            }
            out.append(c);
            prev = c;
        }
        // Collapse multiple hyphens and lowercase
        return out.toString().replaceAll("-+", "-").toLowerCase();
    }
}

