package com.valkyrlabs;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class ThorAPIStressTest {

    private static final String INPUT_YAML = "openapi/api.yaml";
    private static final String TEMPLATE = "openapi/api";
    private static final String OUTPUT_PREFIX = "target/test-output/api-stress-";
    private static final int THREAD_COUNT = 10;

    @Test
    void stressTestThorAPIGeneration() throws InterruptedException {
        // Create output directory
        File outputDir = new File("target/test-output");
        outputDir.mkdirs();
        
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        List<Future<File>> futures = new ArrayList<>();
        List<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int i = 0; i < THREAD_COUNT; i++) {
            futures.add(executor.submit(() -> {
                String outputFile = OUTPUT_PREFIX + UUID.randomUUID() + ".yaml";
                try {
                    ThorAPI.main(new String[]{INPUT_YAML, TEMPLATE, outputFile});
                    File out = new File(outputFile);
                    if (!out.exists() || out.length() == 0) {
                        throw new AssertionError("Output file not created or empty: " + outputFile);
                    }
                    return out;
                } catch (Throwable t) {
                    errors.add(t);
                    throw t;
                }
            }));
        }

        executor.shutdown();
        boolean finished = executor.awaitTermination(5, TimeUnit.MINUTES);
        assertTrue(finished, "Executor did not finish in time");

        for (Future<File> future : futures) {
            try {
                File file = future.get();
                assertTrue(file.exists(), "Output file does not exist: " + file.getAbsolutePath());
                assertTrue(file.length() > 0, "Output file is empty: " + file.getAbsolutePath());
            } catch (ExecutionException e) {
                fail("Exception in thread: " + e);
            }
        }

        assertTrue(errors.isEmpty(), "Errors occurred during stress test: " + errors);
    }
}
