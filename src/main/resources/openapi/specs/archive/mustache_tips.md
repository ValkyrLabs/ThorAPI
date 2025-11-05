

## The Mustache Variables available for java codegen

############ Operation info ############
[ {
  "packageName" : "Org.OpenAPITools",
  "hasImport" : true,
  "modelPackage" : "Org.OpenAPITools.Model",
  "package" : "Org.OpenAPITools.Api",
  "clientPackage" : "Org.OpenAPITools.Client",
  "version" : "1.0.0",
  "classVarName" : "user",
  "basePath" : "http://petstore.swagger.io/v2",
  "packageVersion" : "1.0.0",
  "infoEmail" : "some@email.com",
  "importPath" : "Org.OpenAPITools.Api.User",
  "licenseInfo" : "Apache 2.0",
  "hasMore" : "true",
  "generatedDate" : "2015-10-06T12:20:11.434+08:00",
  "classname" : "UserApi",
  "imports" : [ {
    "import" : "Org.OpenAPITools.Model.User"
  } ],
  "appName" : "Swagger Petstore",
  "appVersion" : "1.0.0",
  "generatorClass" : "class io.swagger.codegen.languages.CSharpClientCodegen",
  "baseName" : "User",
  "contextPath" : "/v2",
  "operations" : {
    "operation" : [ {
      "responseHeaders" : [ ],
      "hasProduces" : true,
      "hasParams" : true,
      "hasMore" : true,
      "isResponseBinary" : false,
      "path" : "/user",
      "operationId" : "CreateUser",
      "httpMethod" : "POST",
      "summary" : "Create user",
      "notes" : "This can only be done by the logged in user.",
      "baseName" : "User",
      "produces" : [ {
        "hasMore" : "true",
        "mediaType" : "application/xml"
      }, {
        "hasMore" : null,
        "mediaType" : "application/json"
      } ],
      "bodyParam" : {
        "isBodyParam" : true,
        "baseName" : "body",
        "paramName" : "body",
        "dataType" : "User",
        "description" : "Created user object",
        "jsonSchema" : "{\n  \"in\" : \"body\",\n  \"name\" : \"body\",\n  \"description\" : \"Created user object\",\n  \"required\" : true,\n  \"schema\" : {\n    \"$ref\" : \"#/definitions/User\"\n  }\n}",
        "isEnum" : false,
        "vendorExtensions" : { },
        "required" : true
      },
      "allParams" : [ {
        "isBodyParam" : true,
        "baseName" : "body",
        "paramName" : "body",
        "dataType" : "User",
        "description" : "Created user object",
        "jsonSchema" : "{\n  \"in\" : \"body\",\n  \"name\" : \"body\",\n  \"description\" : \"Created user object\",\n  \"required\" : true,\n  \"schema\" : {\n    \"$ref\" : \"#/definitions/User\"\n  }\n}",
        "isEnum" : false,
        "vendorExtensions" : { },
        "required" : true
      } ],
      "bodyParams" : [ {
        "isBodyParam" : true,
        "baseName" : "body",
        "paramName" : "body",
        "dataType" : "User",
        "description" : "Created user object",
        "jsonSchema" : "{\n  \"in\" : \"body\",\n  \"name\" : \"body\",\n  \"description\" : \"Created user object\",\n  \"required\" : true,\n  \"schema\" : {\n    \"$ref\" : \"#/definitions/User\"\n  }\n}",
        "isEnum" : false,
        "vendorExtensions" : { },
        "required" : true
      } ],
      "pathParams" : [ ],
      "queryParams" : [ ],
      "headerParams" : [ ],
      "formParams" : [ ],
      "tags" : [ "User" ],
      "responses" : [ {
        "headers" : [ ],
        "code" : "0",
        "message" : "successful operation",
        "hasMore" : false,
        "isDefault" : true,
        "simpleType" : true,
        "primitiveType" : true,
        "isMapContainer" : false,
        "isListContainer" : false,
        "isBinary" : false,
        "jsonSchema" : "{\n  \"description\" : \"successful operation\"\n}",
        "wildcard" : true
      } ],
      "imports" : [ "User" ],
      "vendorExtensions" : { },
      "nickname" : "CreateUser",
      "hasBodyParam" : true,
      "hasQueryParams" : false,
      "hasHeaderParams" : false,
      "hasPathParams" : false,
      "hasFormParams" : false
    }, {