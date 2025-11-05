package com.valkyrlabs.thorapi;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.HashMap;

import org.junit.jupiter.api.Test;

import com.valkyrlabs.ThorAPI;

class TestThorAPI {

    private final String inputspec = System.getProperty("user.dir") + "/src/main/resources/openapi/api.yaml";
    private final String outputspec = System.getProperty("user.dir") + "/src/test/resources/openapi/output-api.yaml";
    private final String templatespec = System.getProperty("user.dir") + "/src/main/resources/openapi/api";

    private String[] args = { inputspec, templatespec, outputspec };

    @Test
    void testInputSchemasInOutputSpec() {

        File output = new File(outputspec);
        if (output.exists()) {
            output.delete();
        }
        assertEquals(false, output.exists(), "test run required to delete the output file");
        try {
            ThorAPI.main(args);
        } catch (Throwable e) {
            e.printStackTrace();
        }

        HashMap<String, Object> testInputPropertyMap = new HashMap<String, Object>();
        testInputPropertyMap.put("field", "x-thor-securefield");
        output = new File(outputspec);

        assertEquals(true, output.exists(), "output api yaml should be written to the output file");
    }
}
