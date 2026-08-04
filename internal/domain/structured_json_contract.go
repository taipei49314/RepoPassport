package domain

const (
	AlphaJSONPathMaxBytes       = 1024
	AlphaJSONSchemaMaxBytes     = int64(256 << 10)
	AlphaJSONSchemaDialect      = "https://json-schema.org/draft/2020-12/schema"
	AlphaJSONValidatorVersion   = "github.com/santhosh-tekuri/jsonschema/v6@v6.0.2"
	AlphaJSONSchemaDigestPrefix = "sha256:"
)
