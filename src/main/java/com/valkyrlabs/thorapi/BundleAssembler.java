package com.valkyrlabs.thorapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Assembles multiple OpenAPI bundle YAML files into a single combined
 * specification.
 * This is a lightweight version of SpecAssemblyService for use in ThorAPI
 * standalone builds.
 */
public class BundleAssembler {

  private static final Logger logger = LoggerFactory.getLogger(BundleAssembler.class);

  private final Yaml yaml;

  public BundleAssembler() {
    DumperOptions options = new DumperOptions();
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
    options.setPrettyFlow(true);
    options.setIndent(2);
    this.yaml = new Yaml(options);
  }

  /**
   * Assembles multiple OpenAPI specification files from a directory
   * into a single combined specification.
   * 
   * @param bundlesDirectory Directory containing bundle YAML files to combine
   * @param outputPath       Path where the combined spec should be written
   * @return true if assembly was successful
   */
  public boolean assembleSpecs(String bundlesDirectory, String outputPath) {
    try {
      Map<String, Object> combinedSpec = assembleSpecsToMap(bundlesDirectory);
      if (combinedSpec == null || combinedSpec.isEmpty()) {
        return false;
      }

      // Write combined spec to output file
      writeSpec(combinedSpec, outputPath);

      logger.info("✅ Successfully assembled bundles into: {}", outputPath);
      return true;

    } catch (Exception e) {
      logger.error("Bundle assembly failed: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Assembles bundle specifications into a single map without writing to disk.
   *
   * @param bundlesDirectory Directory containing bundle YAML files to combine
   * @return Combined specification map, or null if no bundles could be loaded
   */
  public Map<String, Object> assembleSpecsToMap(String bundlesDirectory) {
    try {
      logger.info("Starting bundle assembly from directory: {}", bundlesDirectory);

      List<Map<String, Object>> bundles = loadBundles(bundlesDirectory);
      if (bundles.isEmpty()) {
        logger.warn("No bundle files found in directory: {}", bundlesDirectory);
        return null;
      }

      logger.info("Loaded {} bundle file(s)", bundles.size());
      Map<String, Object> combinedSpec = combineSpecs(bundles);
      logger.info("✅ Successfully assembled {} bundles (in-memory)", bundles.size());
      return combinedSpec;
    } catch (Exception e) {
      logger.error("Bundle assembly failed: {}", e.getMessage(), e);
      return null;
    }
  }

  /**
   * Load all YAML files from bundles directory
   */
  private List<Map<String, Object>> loadBundles(String bundlesDirectory) throws IOException {
    List<Map<String, Object>> bundles = new ArrayList<>();
    File dir = new File(bundlesDirectory);

    if (!dir.exists() || !dir.isDirectory()) {
      logger.warn("Bundles directory does not exist: {}", bundlesDirectory);
      return bundles;
    }

    File[] files = dir.listFiles((d, name) -> name.endsWith(".yaml") || name.endsWith(".yml"));
    if (files == null || files.length == 0) {
      return bundles;
    }

    // Sort files alphabetically for consistent ordering
    Arrays.sort(files);

    for (File file : files) {
      logger.info("Loading bundle: {}", file.getName());
      try (FileInputStream fis = new FileInputStream(file)) {
        @SuppressWarnings("unchecked")
        Map<String, Object> bundle = yaml.load(fis);
        if (bundle != null) {
          bundles.add(bundle);
          logger.info("✓ Loaded bundle: {}", file.getName());
        }
      } catch (Exception e) {
        logger.warn("Failed to load bundle {}: {}", file.getName(), e.getMessage());
      }
    }

    return bundles;
  }

  /**
   * Combine multiple OpenAPI spec fragments into single specification.
   * Intelligently merges: info, servers, tags, paths, components/schemas,
   * securitySchemes
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> combineSpecs(List<Map<String, Object>> bundles) {
    Map<String, Object> combined = new LinkedHashMap<>();

    // Use first bundle's OpenAPI version and info as base
    if (!bundles.isEmpty()) {
      Map<String, Object> first = bundles.get(0);
      if (first.containsKey("openapi")) {
        combined.put("openapi", first.get("openapi"));
      }
      if (first.containsKey("info")) {
        combined.put("info", deepCopy((Map<String, Object>) first.get("info")));
      }
    }

    // Merge servers (combine all unique servers)
    List<Object> allServers = new ArrayList<>();
    Set<String> seenServerUrls = new HashSet<>();
    for (Map<String, Object> bundle : bundles) {
      List<Object> servers = (List<Object>) bundle.get("servers");
      if (servers != null) {
        for (Object server : servers) {
          if (server instanceof Map) {
            String url = (String) ((Map<?, ?>) server).get("url");
            if (url != null && !seenServerUrls.contains(url)) {
              allServers.add(server);
              seenServerUrls.add(url);
            }
          }
        }
      }
    }
    if (!allServers.isEmpty()) {
      combined.put("servers", allServers);
    }

    // Merge tags (combine all unique tags by name)
    List<Object> allTags = new ArrayList<>();
    Set<String> seenTagNames = new HashSet<>();
    for (Map<String, Object> bundle : bundles) {
      List<Object> tags = (List<Object>) bundle.get("tags");
      if (tags != null) {
        for (Object tag : tags) {
          if (tag instanceof Map) {
            String name = (String) ((Map<?, ?>) tag).get("name");
            if (name != null && !seenTagNames.contains(name)) {
              allTags.add(tag);
              seenTagNames.add(name);
            }
          }
        }
      }
    }
    if (!allTags.isEmpty()) {
      combined.put("tags", allTags);
    }

    // Merge paths (combine all paths from all bundles)
    Map<String, Object> allPaths = new LinkedHashMap<>();
    for (Map<String, Object> bundle : bundles) {
      Map<String, Object> paths = (Map<String, Object>) bundle.get("paths");
      if (paths != null) {
        allPaths.putAll(paths);
      }
    }
    if (!allPaths.isEmpty()) {
      combined.put("paths", allPaths);
    }

    // Merge components (schemas, securitySchemes, etc.)
    Map<String, Object> allComponents = new LinkedHashMap<>();
    Map<String, Object> allSchemas = new LinkedHashMap<>();
    Map<String, Object> allSecuritySchemes = new LinkedHashMap<>();

    for (Map<String, Object> bundle : bundles) {
      Map<String, Object> components = (Map<String, Object>) bundle.get("components");
      if (components != null) {
        // Merge schemas
        Map<String, Object> schemas = (Map<String, Object>) components.get("schemas");
        if (schemas != null) {
          for (Map.Entry<String, Object> entry : schemas.entrySet()) {
            if (allSchemas.containsKey(entry.getKey())) {
              logger.info("Schema '{}' already exists, using latest definition", entry.getKey());
            }
            allSchemas.put(entry.getKey(), entry.getValue());
          }
        }

        // Merge securitySchemes
        Map<String, Object> securitySchemes = (Map<String, Object>) components.get("securitySchemes");
        if (securitySchemes != null) {
          allSecuritySchemes.putAll(securitySchemes);
        }
      }
    }

    if (!allSchemas.isEmpty()) {
      allComponents.put("schemas", allSchemas);
    }
    if (!allSecuritySchemes.isEmpty()) {
      allComponents.put("securitySchemes", allSecuritySchemes);
    }
    if (!allComponents.isEmpty()) {
      combined.put("components", allComponents);
    }

    logger.info("Combined spec contains {} schemas, {} paths, {} tags",
        allSchemas.size(), allPaths.size(), allTags.size());

    return combined;
  }

  /**
   * Write combined specification to output file
   */
  private void writeSpec(Map<String, Object> spec, String outputPath) throws IOException {
    File outputFile = new File(outputPath);
    File parentDir = outputFile.getParentFile();
    if (parentDir != null && !parentDir.exists()) {
      parentDir.mkdirs();
    }

    try (FileWriter writer = new FileWriter(outputFile)) {
      yaml.dump(spec, writer);
    }

    logger.info("Combined specification written to: {}", outputPath);
  }

  /**
   * Deep copy a map to avoid reference issues
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> deepCopy(Map<String, Object> original) {
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<String, Object> entry : original.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof Map) {
        copy.put(entry.getKey(), deepCopy((Map<String, Object>) value));
      } else if (value instanceof List) {
        copy.put(entry.getKey(), new ArrayList<>((List<?>) value));
      } else {
        copy.put(entry.getKey(), value);
      }
    }
    return copy;
  }
}
