# ThorAPI

This project contains the ThorAPI, which is a code generator for APIs and client libraries. It uses OpenAPI spec yaml files in conjunction with a templating engine based on swagger codegen.

## Bundle Assembly Workflow

- `src/main/resources/openapi/api.yaml` is a read-only template that declares the REST surface. ThorAPI never mutates this file.
- When a `bundles/` directory sits beside `api.yaml`, ThorAPI assembles the bundle specs into a temporary file (prefixed with `thorapi-assembled-`) in the same directory.
- The temporary spec merges the bundle-generated component definitions with the template-defined sections (paths, parameters, etc.) before the enhancement step runs.
- Only the enhanced output (`api-out.yaml`) is ever written back to disk. The temp file is transient and scheduled for deletion on JVM exit.
- Bundle assembly is disabled by default. Enable it via the `THORAPI_ENABLE_BUNDLES=true` environment variable, the `-Dthorapi.enableBundles=true` system property, or programmatically with `ThorAPI.setBundleAssemblyOverride(true)`. Service flows such as `ThorAPIController` enable the override automatically during generation.
