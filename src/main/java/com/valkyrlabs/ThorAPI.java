package com.valkyrlabs;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import com.github.jknack.handlebars.Handlebars;
import com.github.jknack.handlebars.Template;
import com.github.jknack.handlebars.io.TemplateLoader;
import com.valkyrlabs.thorapi.MapTypeHelper;
import com.valkyrlabs.thorapi.securefield.SecureEncrypter;
import com.valkyrlabs.thorapi.securefield.SecureField;

/**
 * ThorAPI OpenAPI enhancer & generator
 *
 * Usage: java -jar thorapi-*.jar generatekey java -jar thorapi-*.jar
 * <inputYaml> [templateBase] [outputYaml]
 *
 * <inputYaml> : path to input OpenAPI YAML (file path or classpath resource)
 * [templateBase] : classpath id (e.g. openapi/api) OR filesystem base path
 * (without .hbs.yaml) [outputYaml] : output file path (default: <inputYaml
 * dir>/api-out.yaml)
 */
public class ThorAPI {

    protected static final Logger logger = LoggerFactory.getLogger(ThorAPI.class);

    // Legacy defaults (kept for compatibility, but arguments take precedence)
    public static final String OPEN_API_OUTPUT_FILE = "valkyrai/src/main/resources/openapi/api-out.yaml";
    public static final String OPEN_API_INPUT_YAML_FILE = "valkyrai/src/main/resources/openapi/api.yaml";
    public static final String OPEN_API_TEMPLATE_YAML_FILE = "src/main/resources/openapi/api";

    private static final int CIPHER_TEXT_SIZE_FACTOR = 3;
    private static final String EXTRA_ANNOTATION = "x-field-extra-annotation";
    private static final ThreadLocal<Boolean> bundleAssemblyOverride = new ThreadLocal<>();
    private static final String BUNDLE_SYS_PROP = "thorapi.enableBundles";
    private static final String BUNDLE_ENV_VAR = "THORAPI_ENABLE_BUNDLES";

    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException {
        if (args.length < 1) {
            showUsage();
        }

        if ("generatekey".equalsIgnoreCase(args[0].trim())) {
            generateKey();
        }

        // ---------------------------
        // Parse arguments
        // ---------------------------
        final String inputYaml = args[0].trim();
        String templateBase = (args.length > 1 ? args[1].trim() : OPEN_API_TEMPLATE_YAML_FILE);
        String outputYaml;
        if (args.length > 2) {
            outputYaml = args[2].trim();
        } else {
            File in = new File(inputYaml);
            File parent = in.getParentFile();
            File out = new File(parent == null ? new File(".") : parent, "api-out.yaml");
            outputYaml = out.getAbsolutePath();
        }

        logger.info("ARGS => inputYaml='{}' templateBase='{}' outputYaml='{}'", inputYaml, templateBase, outputYaml);

        // ---------------------------
        // STEP 1: Assemble bundles if bundles directory exists
        // ---------------------------
        String assembledYaml = assembleBundlesIfPresent(inputYaml);
        final String specToEnhance = assembledYaml != null ? assembledYaml : inputYaml;

        // ---------------------------
        // STEP 2: Load input YAML (classpath or filesystem)
        // ---------------------------
        Yaml yaml = new Yaml();
        InputStream inputStream;
        InputStream cpStream = ThorAPI.class.getClassLoader().getResourceAsStream(specToEnhance);
        if (cpStream != null) {
            inputStream = new BufferedInputStream(cpStream);
            logger.info("Loaded input YAML from classpath: {}", specToEnhance);
        } else if (new File(specToEnhance).exists()) {
            inputStream = new BufferedInputStream(new FileInputStream(specToEnhance));
            logger.info("Loaded input YAML from file: {}", specToEnhance);
        } else {
            logger.error("Input YAML not found: {}", specToEnhance);
            System.exit(-1);
            return;
        }

        logger.debug("Input YAML available bytes: {}", inputStream.available());
        Map<String, Object> obj;
        try (InputStream is = inputStream) {
            obj = yaml.load(is);
        }
        Map<String, Object> components = getComponents(obj);

        // ---------------------------
        // Resolve template (filesystem absolute/relative OR classpath)
        // ---------------------------
        Handlebars handlebars = new Handlebars();
        handlebars.registerHelper("mapType", new MapTypeHelper());
        handlebars.registerHelper("kebab", new com.valkyrlabs.thorapi.KebabCaseHelper());

        final String suffix = ".hbs.yaml";
        Template template;
        String processedTemplateContent;

        // Try filesystem first if caller passed a path that points to a file
        File templateFile = new File(templateBase.endsWith(suffix) ? templateBase : templateBase + suffix);
        if ((templateFile.isAbsolute() || templateFile.getPath().contains(File.separator)) && templateFile.exists()) {
            String baseDir = templateFile.getParent();
            String baseName = templateFile.getName();
            if (baseName.endsWith(suffix)) {
                baseName = baseName.substring(0, baseName.length() - suffix.length());
            }
            com.github.jknack.handlebars.io.FileTemplateLoader ftl = new com.github.jknack.handlebars.io.FileTemplateLoader(
                    baseDir == null ? "." : baseDir, "");
            ftl.setSuffix(suffix);
            handlebars.with(ftl);
            logger.info("Using filesystem template: {} (baseDir='{}', name='{}')", templateFile.getAbsolutePath(),
                    baseDir, baseName);
            Path templatePath = templateFile.toPath();
            String templateContent = Files.readString(templatePath, StandardCharsets.UTF_8);
            Path includePath = resolveIncludePath(templatePath, suffix);
            String includeContent = null;
            if (includePath != null && Files.exists(includePath)) {
                logger.info("Injecting supplemental template from file: {}", includePath);
                includeContent = Files.readString(includePath, StandardCharsets.UTF_8);
            } else {
                logger.debug("No supplemental template found next to {}", templatePath);
            }
            processedTemplateContent = injectIncludeUnderPaths(templateContent, includeContent,
                    includePath != null ? includePath.toString() : templatePath.toString());
            template = handlebars.compileInline(processedTemplateContent);
        } else {
            // Fallback to classpath (e.g., "openapi/api")
            String cpPath = templateBase.endsWith(suffix) ? templateBase : templateBase + suffix;
            InputStream check = ThorAPI.class.getClassLoader().getResourceAsStream(cpPath);
            if (check == null) {
                logger.error("Template not found. Tried file: {} and classpath: {}", templateFile.getAbsolutePath(),
                        cpPath);
                System.exit(-1);
                return;
            }
            if (check != null) {
                try {
                    check.close();
                } catch (IOException ignore) {
                }
            }
            com.github.jknack.handlebars.io.ClassPathTemplateLoader cptl = new com.github.jknack.handlebars.io.ClassPathTemplateLoader(
                    "/", "");
            cptl.setSuffix(suffix);
            handlebars.with(cptl);
            String logicalName = cpPath.startsWith("/") ? cpPath.substring(1) : cpPath;
            logicalName = logicalName.substring(0, logicalName.length() - suffix.length());
            logger.info("Using classpath template: {} (logical='{}')", cpPath, logicalName);
            String templateContent = readClasspathResource(cpPath);
            if (templateContent == null) {
                throw new IOException("Failed to load classpath template: " + cpPath);
            }
            String includeResource = (logicalName + "_inc" + suffix);
            String includeContent = readClasspathResource(includeResource);
            if (includeContent != null) {
                logger.info("Injecting supplemental template from classpath resource: {}", includeResource);
            } else {
                logger.debug("No supplemental classpath template found for {}", includeResource);
            }
            processedTemplateContent = injectIncludeUnderPaths(templateContent, includeContent, includeResource);
            template = handlebars.compileInline(processedTemplateContent);
        }

        // ---------------------------
        // Render, enhance, and write
        // ---------------------------
        String output = template.apply(components);
        Map<String, Object> rootObject = yaml.load(output);

        Map<String, Object> recomponents = cast(rootObject.get("components"));
        Map<String, Object> reschemas = cast(recomponents.get("schemas"));
        enhanceOpenAPI(obj, rootObject, reschemas);

        output = yaml.dump(rootObject);

        File outFile = new File(outputYaml);
        File parentDir = outFile.getParentFile();
        if (parentDir != null && !parentDir.exists() && !parentDir.mkdirs()) {
            logger.warn("Could not create output directory: {}", parentDir);
        }
        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.write(output);
        }
        logger.info("Wrote enhanced OpenAPI to: {} (exists={})", outFile.getAbsolutePath(), outFile.exists());
    }

    private static Path resolveIncludePath(Path templatePath, String suffix) {
        if (templatePath == null) {
            return null;
        }
        String fileName = templatePath.getFileName().toString();
        String baseName = fileName.endsWith(suffix) ? fileName.substring(0, fileName.length() - suffix.length())
                : fileName;
        Path parent = templatePath.getParent();
        if (parent != null) {
            return parent.resolve(baseName + "_inc" + suffix);
        }
        return Path.of(baseName + "_inc" + suffix);
    }

    private static String readClasspathResource(String resourcePath) throws IOException {
        if (resourcePath == null) {
            return null;
        }
        String normalized = resourcePath.startsWith("/") ? resourcePath.substring(1) : resourcePath;
        try (InputStream in = ThorAPI.class.getClassLoader().getResourceAsStream(normalized)) {
            if (in == null) {
                logger.debug("Classpath resource not found: {}", resourcePath);
                return null;
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String injectIncludeUnderPaths(String templateContent, String includeContent, String includeId) {
        if (includeContent == null || includeContent.isBlank()) {
            return templateContent;
        }

        Pattern pattern = Pattern.compile("(?m)^(\\s*)paths\\s*:\\s*$");
        Matcher matcher = pattern.matcher(templateContent);
        if (!matcher.find()) {
            logger.warn("paths: section not found; skipping include {}", includeId);
            return templateContent;
        }

        int insertPos = matcher.end();
        String lineSep = detectLineSeparator(templateContent);
        String prefix = "";

        if (templateContent.startsWith("\r\n", insertPos)) {
            insertPos += 2;
        } else if (templateContent.startsWith("\n", insertPos)) {
            insertPos += 1;
        } else if (templateContent.startsWith("\r", insertPos)) {
            insertPos += 1;
        } else {
            prefix = lineSep;
        }

        String includeBlock = includeContent;
        if (!"\n".equals(lineSep)) {
            includeBlock = includeBlock.replace("\r\n", "\n").replace("\r", "\n");
            includeBlock = includeBlock.replace("\n", lineSep);
        }
        if (!includeBlock.endsWith(lineSep)) {
            includeBlock = includeBlock + lineSep;
        }

        logger.info("Injecting supplemental template '{}' under paths:", includeId);
        return templateContent.substring(0, insertPos) + prefix + includeBlock + templateContent.substring(insertPos);
    }

    private static String detectLineSeparator(String text) {
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch == '\r') {
                if (i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    return "\r\n";
                }
                return "\r";
            } else if (ch == '\n') {
                return "\n";
            }
        }
        return System.lineSeparator();
    }

    private static void showUsage() {
        System.err.println("usage:");
        System.err.println("  java -jar thorapi-*.jar generatekey");
        System.err.println("  java -jar thorapi-*.jar <inputYaml> [templateBase] [outputYaml]");
        System.err.println("    <inputYaml>    : path to input OpenAPI YAML (file or classpath)");
        System.err
                .println("    [templateBase] : classpath id (e.g. openapi/api) OR filesystem base path (no .hbs.yaml)");
        System.err.println("    [outputYaml]   : output file path (default: <inputDir>/api-out.yaml)");
        System.exit(0);
    }

    private static void generateKey() throws InvalidAlgorithmParameterException {
        System.out.println("Generate ThorAPI SecureField Secret Key  --------------");
        System.out.println("-------------------------------------------------------");
        System.out.println();
        try {
            String key = SecureEncrypter.generateUrlEncodedSecretKey();
            System.out.println(key);
        } catch (NoSuchAlgorithmException e) {
            logger.error("ThorAPI SecureField FAILURE!!!. Check Configurations. {} ", e.getMessage());
        }
        System.out.println();
        System.out.println("-------------------------------------------------------");
        System.exit(0);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ensureComponentSection(Map<String, Object> components, String sectionName) {
        if (components == null) {
            throw new IllegalArgumentException("components map must not be null");
        }

        Object existing = components.get(sectionName);
        if (existing instanceof Map<?, ?>) {
            return (Map<String, Object>) existing;
        }

        Map<String, Object> created = new LinkedHashMap<>();
        components.put(sectionName, created);
        return created;
    }

    @SuppressWarnings("unchecked")
    private static void mergeOriginalComponents(Map<String, Object> targetComponents,
            Map<String, Object> originalComponents) {
        if (targetComponents == null || originalComponents == null || originalComponents.isEmpty()) {
            return;
        }

        for (Map.Entry<String, Object> entry : originalComponents.entrySet()) {
            String sectionName = entry.getKey();
            Object originalSection = entry.getValue();

            if (originalSection instanceof Map<?, ?>) {
                Map<String, Object> originalMap = (Map<String, Object>) originalSection;
                Map<String, Object> targetSection = ensureComponentSection(targetComponents, sectionName);
                for (Map.Entry<String, Object> originalEntry : originalMap.entrySet()) {
                    targetSection.putIfAbsent(originalEntry.getKey(), originalEntry.getValue());
                }
            } else if (!targetComponents.containsKey(sectionName)) {
                targetComponents.put(sectionName, originalSection);
            }
        }
    }

    // ---------------------------
    // Enhancement pipeline
    // ---------------------------
    private static void enhanceOpenAPI(Map<String, Object> obj, Map<String, Object> rootObject,
            Map<String, Object> reschemas) {
        Object infos = obj.get("info");
        Map<String, Object> paths = cast(obj.get("paths"));
        Object tags = obj.get("tags");

        Object servers = obj.get("servers");
        Object externalDocs = obj.get("externalDocs");

        extractedInfos(rootObject, reschemas, infos);

        logger.debug("INJECTING THORAPI PATHS: {}", paths);
        injectPathSection(rootObject, paths);

        logger.info("INJECTING THORAPI TAGS: {}", tags);
        if (tags != null) {
            replaceTagsSection(rootObject, tags);
        } else {
            try {
                logger.warn("NO TAGS IN: {}", obj.get("description"));
            } catch (Exception e) {
                // ignore
            }
        }

        logger.debug("INJECTING THORAPI SERVERS: {}", servers);
        replaceServersSection(rootObject, servers);

        logger.debug("INJECTING THORAPI EXTERNAL DOCS: {}", servers);
        replaceExternalDocsSection(rootObject, externalDocs);

        // order stabilization (no-ops but explicit)
        rootObject.put("paths", rootObject.get("paths"));
        rootObject.put("components", rootObject.get("components"));

        logger.debug("INJECTING THORAPI PROPS: {}", reschemas.keySet());
        injectAdditionalProperties(reschemas);
    }

    private static void extractedInfos(Map<String, Object> rootObject, Map<String, Object> reschemas, Object infos) {
        logger.debug("INSPECTING {} THORAPI SCHEMAS", reschemas.size());
        for (String schema : reschemas.keySet()) {
            logger.debug("GENERATED: {}", schema);
        }
        logger.info("INJECTING THORAPI INFO: {}", infos);
        replaceInfoSection(rootObject, infos);
    }

    public static Map<String, Object> processOpenAPISpecWithJavaSpringTemplate(String inputYamlPath,
            String outputYamlPath) throws IOException, InvalidAlgorithmParameterException {

        logger.info("Processing OpenAPI spec with JavaSpring template: {} -> {}", inputYamlPath, outputYamlPath);

        Yaml yaml = new Yaml();

        InputStream resourceStream = ThorAPI.class.getClassLoader().getResourceAsStream(inputYamlPath);
        InputStream inputStream;
        if (resourceStream != null) {
            inputStream = new BufferedInputStream(resourceStream);
            logger.info("LOADED input YAML from classpath resource: {}", inputYamlPath);
        } else {
            inputStream = new BufferedInputStream(new FileInputStream(inputYamlPath));
            logger.info("LOADED input YAML from file system: {}", inputYamlPath);
        }

        logger.debug("Input YAML available bytes: {}", inputStream.available());
        Map<String, Object> obj = yaml.load(inputStream);
        Map<String, Object> components = getComponents(obj);

        Handlebars handlebars = new Handlebars();
        handlebars.registerHelper("mapType", new MapTypeHelper());
        handlebars.registerHelper("kebab", new com.valkyrlabs.thorapi.KebabCaseHelper());

        String openApiTemplate = "openapi/api";
        TemplateLoader loader = new com.github.jknack.handlebars.io.ClassPathTemplateLoader();
        loader.setSuffix(".hbs.yaml");
        logger.info("Using classpath template loader for: {}", openApiTemplate);

        handlebars.with(loader);
        Template template = handlebars.compile(openApiTemplate);

        String output = template.apply(components);
        Map<String, Object> rootObject = yaml.load(output);

        Map<String, Object> recomponents = cast(rootObject.get("components"));
        if (recomponents == null) {
            recomponents = new LinkedHashMap<>();
            rootObject.put("components", recomponents);
        }

        Map<String, Object> originalComponents = cast(obj.get("components"));
        mergeOriginalComponents(recomponents, originalComponents);

        Map<String, Object> reschemas = ensureComponentSection(recomponents, "schemas");

        enhanceOpenAPI(obj, rootObject, reschemas);

        output = yaml.dump(rootObject);

        File outFile = new File(outputYamlPath);
        File parentDir = outFile.getParentFile();
        if (parentDir != null && !parentDir.exists() && !parentDir.mkdirs()) {
            logger.warn("Could not create output directory: {}", parentDir);
        }
        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.write(output);
        }

        logger.info("DONE OPENAPI File {} written: {}", outFile.getAbsolutePath(), outFile.exists());
        return components;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getComponents(Map<String, Object> obj) {
        Map<String, Object> components = (Map<String, Object>) obj.get("components");
        logger.info("LOADED {} input YAML components", components.size());
        for (String component : components.keySet()) {
            logger.info("LOADED from input: {}", component);
        }
        return components;
    }

    static void replaceServersSection(Map<String, Object> rootObject, Object servers) {
        if (rootObject != null && servers != null) {
            rootObject.put("servers", servers);
        } else {
            logger.warn("Could not inject servers section");
        }
    }

    static void replaceTagsSection(Map<String, Object> rootObject, Object tags) {
        if (rootObject != null && tags != null) {
            rootObject.put("tags", tags);
        } else {
            logger.warn("Could not inject tags section");
        }
    }

    @SuppressWarnings("unchecked")
    static void injectPathSection(Map<String, Object> rootObject, Map<String, Object> paths) {
        try {
            if (rootObject != null && paths != null) {
                Map<String, Object> outputPaths = (Map<String, Object>) rootObject.get("paths");
                if (outputPaths == null) {
                    outputPaths = new java.util.LinkedHashMap<>();
                    rootObject.put("paths", outputPaths);
                }
                for (String key : paths.keySet()) {
                    outputPaths.put(key, paths.get(key));
                }
            } else {
                logger.warn("Could not inject paths section");
            }
        } catch (Exception e) {
            logger.warn("Exception while injecting paths section", e);
        }
    }

    static void replaceInfoSection(Map<String, Object> rootObject, Object info) {
        if (rootObject != null && info != null) {
            rootObject.put("info", info);
        } else {
            logger.warn("Could not inject info section");
        }
    }

    static void replaceExternalDocsSection(Map<String, Object> rootObject, Object externalDocs) {
        if (rootObject != null && externalDocs != null) {
            rootObject.put("externalDocs", externalDocs);
        } else {
            logger.warn("Could not inject externalDocs section");
        }
    }

    private static void injectAdditionalProperties(Map<String, Object> schemas) {
        for (Map.Entry<String, Object> entry : schemas.entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> schema = (Map<String, Object>) entry.getValue();
            if (schema != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
                if (properties != null) {
                    properties.put("id", iDProperty());
                    properties.put("ownerId", ownerIDProperty());
                    properties.put("createdDate", createdDateProperty());
                    properties.put("keyHash", createdKeyHashProperty());
                    properties.put("lastAccessedById", lastAccessedByIdProperty());
                    properties.put("lastAccessedDate", lastAccessedDateProperty());
                    properties.put("lastModifiedById", lastModifiedByIDProperty());
                    properties.put("lastModifiedDate", lastModifiedDateProperty());

                    for (Map.Entry<String, Object> entryx : properties.entrySet()) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> value = (Map<String, Object>) entryx.getValue();
                        if (value == null)
                            continue;

                        if (!(value instanceof java.util.LinkedHashMap) && !(value instanceof java.util.HashMap)) {
                            value = new LinkedHashMap<>(value);
                            properties.put(entryx.getKey(), value);
                        }

                        Object longTextLength = value.get("maxLength");
                        Object secureObj = value.get("x-thorapi-secureField");
                        Object dataFieldObj = value.get("x-thorapi-dataField");

                        boolean isSecure = (secureObj != null);
                        boolean isDataField = (dataFieldObj != null);
                        boolean isLongText = (longTextLength != null);

                        List<String> annotations = new ArrayList<>();
                        Object existingAnnotations = value.get(EXTRA_ANNOTATION);
                        if (existingAnnotations instanceof String existing && !existing.isBlank()) {
                            for (String line : existing.split("\\R")) {
                                if (line != null && !line.isBlank()) {
                                    annotations.add(line);
                                }
                            }
                        }

                        Map<String, String> dataFieldAttributes = isDataField
                                ? parseDataFieldAttributes(dataFieldObj)
                                : new HashMap<>();

                        boolean dataFieldUnique = Boolean
                                .parseBoolean(dataFieldAttributes.getOrDefault("unique", "false"));
                        boolean dataFieldHidden = Boolean
                                .parseBoolean(dataFieldAttributes.getOrDefault("hidden", "false"));
                        boolean dataFieldAdvanced = Boolean
                                .parseBoolean(dataFieldAttributes.getOrDefault("advanced", "false"));

                        if (isLongText) {
                            int ltl = Integer.parseInt(longTextLength.toString());
                            if (isSecure) {
                                ltl = ltl * CIPHER_TEXT_SIZE_FACTOR; // allow ciphertext expansion
                            }
                            logger.info("LONGTEXT EXTENSION: {} for field: {}", ltl, entryx.getKey());
                            removeAnnotationsStartingWith(annotations, "@Column(");
                            annotations.add(0, buildColumnAnnotation(ltl, dataFieldUnique));
                        } else if (dataFieldUnique) {
                            ensureColumnUnique(annotations);
                        }

                        if (isSecure) {
                            logger.info("Adding SecureField EXTENSION on {} => {}", entryx.getKey(), secureObj);
                            annotations.add(0, buildSecureFieldAnnotation());
                        }

                        if (isDataField) {
                            logger.info("Adding DataField metadata for {} => {}", entryx.getKey(), dataFieldObj);
                            annotations.add(0,
                                    buildDataFieldAnnotation(dataFieldUnique, dataFieldHidden, dataFieldAdvanced));
                        }

                        if (!annotations.isEmpty()) {
                            value.put(EXTRA_ANNOTATION, String.join("\n", annotations));
                        } else {
                            value.remove(EXTRA_ANNOTATION);
                        }
                    }
                }
            }
        }
    }

    static Map<String, Object> createdKeyHashProperty() {
        return Map.of("type", "string", "description",
                "Data, including hash of the key(s) used to encrypt this record.");
    }

    static Map<String, Object> createdDateProperty() {
        return Map.of("type", "string", "description", "Date of object creation", "format", "date-time",
                EXTRA_ANNOTATION,
                "        @AuditingField(fieldType = AuditingField.FieldType.CREATED_DATE, enabled = true)", "example",
                getFormattedDate());
    }

    static Map<String, Object> lastAccessedByIdProperty() {
        return Map.of("type", "string", "description", "Last user to access object", "format", "uuid", EXTRA_ANNOTATION,
                "        @AuditingField(fieldType = AuditingField.FieldType.LAST_ACCESSED_BY, enabled = true)",
                "example", UUID.randomUUID().toString());
    }

    static Map<String, Object> lastAccessedDateProperty() {
        return Map.of("type", "string", "description", "Timestamp of last access of object", "format", "date-time",
                EXTRA_ANNOTATION,
                "        @AuditingField(fieldType = AuditingField.FieldType.LAST_ACCESSED_DATE, enabled = true)",
                "example", getFormattedDate());
    }

    static Map<String, Object> lastModifiedByIDProperty() {
        return Map.of("type", "string", "description",
                "Unique identifier for user who last modifed the object in the system", "format", "uuid",
                EXTRA_ANNOTATION,
                "        @AuditingField(fieldType = AuditingField.FieldType.LAST_MODIFIED_BY, enabled = true)",
                "example", UUID.randomUUID().toString());
    }

    static Map<String, Object> lastModifiedDateProperty() {
        return Map.of("type", "string", "description", "Date of last object modification", "format", "date-time",
                EXTRA_ANNOTATION,
                "    @AuditingField(fieldType = AuditingField.FieldType.LAST_MODIFIED_DATE, enabled = true)", "example",
                getFormattedDate());
    }

    static Map<String, Object> iDProperty() {
        return Map.of("type", "string", "description", "Unique identifier for object in the system", "format", "uuid",
                EXTRA_ANNOTATION, "@Id  \n        @GeneratedValue(generator = \"UUID\")\n", "example",
                UUID.randomUUID().toString());
    }

    static Map<String, Object> ownerIDProperty() {
        return Map.of("type", "string", "description", "UUID of owner of the object in the system", "format", "uuid",
                EXTRA_ANNOTATION,
                "        @AuditingField(fieldType = AuditingField.FieldType.CREATED_BY, enabled = true)", "example",
                UUID.randomUUID().toString());
    }

    private static Map<String, String> parseDataFieldAttributes(Object dataFieldObj) {
        Map<String, String> attributes = new HashMap<>();
        if (dataFieldObj == null) {
            return attributes;
        }
        if (dataFieldObj instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    attributes.put(entry.getKey().toString().trim(), entry.getValue().toString().trim());
                }
            }
            return attributes;
        }

        String raw = dataFieldObj.toString();
        for (String token : raw.split(",")) {
            String trimmed = token.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.contains("=")) {
                String[] pair = trimmed.split("=", 2);
                attributes.put(pair[0].trim(), pair.length > 1 ? pair[1].trim() : "");
            } else {
                attributes.put(trimmed, "true");
            }
        }
        return attributes;
    }

    private static void removeAnnotationsStartingWith(List<String> annotations, String prefix) {
        annotations.removeIf(line -> line != null && line.trim().startsWith(prefix));
    }

    private static String buildColumnAnnotation(int length, boolean unique) {
        StringBuilder sb = new StringBuilder("@Column(length = ").append(length);
        if (unique) {
            sb.append(", unique = true");
        }
        sb.append(")");
        return sb.toString();
    }

    private static String buildSecureFieldAnnotation() {
        return "@SecureField(encryptionType = SecureField.EncryptionType." + SecureField.EncryptionType.SYMMETRIC
                + ", strength = " + 5 + ")";
    }

    private static String buildDataFieldAnnotation(boolean unique, boolean hidden, boolean advanced) {
        return "@DataField(unique = " + unique + ", hidden = " + hidden + ", advanced = " + advanced + ")";
    }

    private static void ensureColumnUnique(List<String> annotations) {
        for (int i = 0; i < annotations.size(); i++) {
            String line = annotations.get(i);
            if (line != null) {
                String trimmed = line.trim();
                if (trimmed.startsWith("@Column(") && !trimmed.contains("unique")) {
                    annotations.set(i, insertUniqueIntoColumn(line));
                    return;
                } else if (trimmed.startsWith("@Column(") && trimmed.contains("unique")) {
                    return;
                }
            }
        }
        annotations.add(0, "@Column(unique = true)");
    }

    private static String insertUniqueIntoColumn(String columnAnnotation) {
        int closingIndex = columnAnnotation.lastIndexOf(')');
        if (closingIndex < 0) {
            return columnAnnotation;
        }
        String prefix = columnAnnotation.substring(0, closingIndex);
        if (prefix.contains("unique")) {
            return columnAnnotation;
        }
        String separator = prefix.trim().endsWith("(") ? "" : ", ";
        return prefix + separator + "unique = true)";
    }

    /**
     * Assemble OpenAPI bundles into a temporary spec while leaving the source
     * api.yaml untouched. The temp spec combines bundled components with the
     * template-defined sections (e.g., paths).
     *
     * @param inputYaml Path to the input OpenAPI YAML file
     * @return Path to assembled temp YAML if bundles were merged, otherwise null
     */
    private static String assembleBundlesIfPresent(String inputYaml) {
        if (!isBundleAssemblyEnabled()) {
            logger.debug("ThorAPI bundle assembly disabled; using base spec: {}", inputYaml);
            return null;
        }

        try {
            File inputFile = new File(inputYaml);
            File parentDir = inputFile.getParentFile();
            if (parentDir == null) {
                logger.debug("No parent directory for input YAML, skipping bundle assembly");
                return null;
            }

            File bundlesDir = new File(parentDir, "bundles");
            if (!bundlesDir.exists() || !bundlesDir.isDirectory()) {
                logger.debug("No bundles directory found at {}, skipping bundle assembly",
                        bundlesDir.getAbsolutePath());
                return null;
            }

            logger.info("✨ Found bundles directory at {}, assembling bundles...", bundlesDir.getAbsolutePath());

            com.valkyrlabs.thorapi.BundleAssembler assembler = new com.valkyrlabs.thorapi.BundleAssembler();
            Map<String, Object> assembledSpec = assembler.assembleSpecsToMap(bundlesDir.getAbsolutePath());
            if (assembledSpec == null || assembledSpec.isEmpty()) {
                logger.warn("⚠️  Bundle assembly produced no data, using original spec");
                return null;
            }

            Map<String, Object> templateSpec = loadTemplateSpecSafely(inputFile);
            Map<String, Object> mergedSpec = mergeBundledSpecWithTemplate(assembledSpec, templateSpec);

            Path tempFile = Files.createTempFile(parentDir.toPath(), "thorapi-assembled-", ".yaml");
            writeYamlToFile(mergedSpec, tempFile);
            tempFile.toFile().deleteOnExit();

            logger.info("✅ Bundle assembly SUCCESSFUL - wrote merged spec to temp file {}", tempFile.toAbsolutePath());
            return tempFile.toAbsolutePath().toString();
        } catch (Exception e) {
            logger.warn("Bundle assembly encountered error (continuing with original spec): {}", e.getMessage(), e);
            return null;
        }
    }

    private static Map<String, Object> loadTemplateSpecSafely(File inputFile) {
        if (inputFile == null || !inputFile.exists()) {
            logger.warn("Template YAML {} not found; continuing with bundled spec only", inputFile);
            return null;
        }
        Yaml yaml = new Yaml();
        try (InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile))) {
            Object loaded = yaml.load(inputStream);
            if (loaded instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> casted = (Map<String, Object>) map;
                return casted;
            }
            logger.warn("Template YAML {} did not resolve to a map structure; ignoring template data", inputFile);
        } catch (Exception ex) {
            logger.warn("Failed to read template YAML {}: {}", inputFile, ex.getMessage());
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mergeBundledSpecWithTemplate(Map<String, Object> assembledSpec,
            Map<String, Object> templateSpec) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (assembledSpec != null) {
            merged.putAll(assembledSpec);
        }

        if (templateSpec == null || templateSpec.isEmpty()) {
            return merged;
        }

        copyIfAbsent(merged, templateSpec, "info");
        copyIfAbsent(merged, templateSpec, "servers");
        copyIfAbsent(merged, templateSpec, "tags");
        copyIfAbsent(merged, templateSpec, "externalDocs");
        copyIfAbsent(merged, templateSpec, "security");
        copyIfAbsent(merged, templateSpec, "webhooks");

        Object templatePaths = templateSpec.get("paths");
        if (templatePaths instanceof Map<?, ?> templatePathsMap && !templatePathsMap.isEmpty()) {
            merged.put("paths", deepCopyMap((Map<String, Object>) templatePathsMap));
        }

        Map<String, Object> bundledComponents = assembledSpec != null
                ? cast(assembledSpec.get("components"))
                : null;
        Map<String, Object> templateComponents = cast(templateSpec.get("components"));

        if (templateComponents != null || bundledComponents != null) {
            Map<String, Object> mergedComponents = new LinkedHashMap<>();
            if (templateComponents != null) {
                mergedComponents.putAll(deepCopyMap(templateComponents));
            }
            if (bundledComponents != null) {
                for (Map.Entry<String, Object> entry : bundledComponents.entrySet()) {
                    Object existing = mergedComponents.get(entry.getKey());
                    if (existing instanceof Map<?, ?> existingMap && entry.getValue() instanceof Map<?, ?> bundleMap) {
                        Map<String, Object> mergedSection = deepCopyMap((Map<String, Object>) existingMap);
                        mergedSection.putAll(deepCopyMap((Map<String, Object>) bundleMap));
                        mergedComponents.put(entry.getKey(), mergedSection);
                    } else {
                        mergedComponents.put(entry.getKey(), entry.getValue());
                    }
                }
            }
            merged.put("components", mergedComponents);
        }

        return merged;
    }

    private static void copyIfAbsent(Map<String, Object> target, Map<String, Object> source, String key) {
        if (target.containsKey(key)) {
            return;
        }
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private static Map<String, Object> deepCopyMap(Map<String, Object> original) {
        if (original == null) {
            return null;
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : original.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> mapValue) {
                @SuppressWarnings("unchecked")
                Map<String, Object> child = (Map<String, Object>) mapValue;
                copy.put(entry.getKey(), deepCopyMap(child));
            } else if (value instanceof List<?> listValue) {
                copy.put(entry.getKey(), deepCopyList(listValue));
            } else {
                copy.put(entry.getKey(), value);
            }
        }
        return copy;
    }

    private static List<Object> deepCopyList(List<?> original) {
        if (original == null) {
            return null;
        }
        List<Object> copy = new ArrayList<>(original.size());
        for (Object item : original) {
            if (item instanceof Map<?, ?> mapItem) {
                @SuppressWarnings("unchecked")
                Map<String, Object> child = (Map<String, Object>) mapItem;
                copy.add(deepCopyMap(child));
            } else if (item instanceof List<?> listItem) {
                copy.add(deepCopyList(listItem));
            } else {
                copy.add(item);
            }
        }
        return copy;
    }

    private static void writeYamlToFile(Map<String, Object> data, Path target) throws IOException {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setIndent(2);
        Yaml dumper = new Yaml(options);
        try (Writer writer = new BufferedWriter(
                Files.newBufferedWriter(target, StandardCharsets.UTF_8))) {
            dumper.dump(data, writer);
        }
    }

    private static boolean isBundleAssemblyEnabled() {
        Boolean override = bundleAssemblyOverride.get();
        if (override != null) {
            return override.booleanValue();
        }

        String envValue = System.getenv(BUNDLE_ENV_VAR);
        if (envValue != null) {
            return parseBooleanValue(envValue);
        }

        String sysProp = System.getProperty(BUNDLE_SYS_PROP);
        if (sysProp != null) {
            return parseBooleanValue(sysProp);
        }

        return false;
    }

    private static boolean parseBooleanValue(String raw) {
        if (raw == null) {
            return false;
        }
        String normalized = raw.trim().toLowerCase();
        return normalized.equals("true")
                || normalized.equals("1")
                || normalized.equals("yes")
                || normalized.equals("y")
                || normalized.equals("on");
    }

    /**
     * Override bundle assembly flag for the current thread. Pass {@code null} to
     * remove the override.
     */
    public static void setBundleAssemblyOverride(Boolean enabled) {
        if (enabled == null) {
            bundleAssemblyOverride.remove();
        } else {
            bundleAssemblyOverride.set(enabled);
        }
    }

    static String getFormattedDate() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        Date dtx = new Date();
        return sdf.format(dtx);
    }
}
