package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAPIResponseSchemaCoversGoJSONFields(t *testing.T) {
	schema := readSchemaDefs(t)
	assertStructMatchesSchema(t, reflect.TypeOf(APIResponse{}), schema, "APIResponse")
	assertStructMatchesSchema(t, reflect.TypeOf(LookupResult{}), schema, "LookupResult")
	assertStructMatchesSchema(t, reflect.TypeOf(SourceInfo{}), schema, "SourceInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(SourceError{}), schema, "SourceError")
	assertStructMatchesSchema(t, reflect.TypeOf(DomainInfo{}), schema, "DomainInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(RegistryInfo{}), schema, "RegistryInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(RegistrarInfo{}), schema, "RegistrarInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(Brand{}), schema, "Brand")
	assertStructMatchesSchema(t, reflect.TypeOf(DateInfo{}), schema, "DateInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(DomainStatus{}), schema, "DomainStatus")
	assertStructMatchesSchema(t, reflect.TypeOf(Nameserver{}), schema, "Nameserver")
	assertStructMatchesSchema(t, reflect.TypeOf(DNSSECInfo{}), schema, "DNSSECInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(RegistrantInfo{}), schema, "RegistrantInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(NetworkInfo{}), schema, "NetworkInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(DNSInfo{}), schema, "DNSInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(DNSAddress{}), schema, "DNSAddress")
	assertStructMatchesSchema(t, reflect.TypeOf(DNSMX{}), schema, "DNSMX")
	assertStructMatchesSchema(t, reflect.TypeOf(DNSVizInfo{}), schema, "DNSVizInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(PricingInfo{}), schema, "PricingInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(MozInfo{}), schema, "MozInfo")
	assertStructMatchesSchema(t, reflect.TypeOf(RawData{}), schema, "RawData")
	assertStructMatchesSchema(t, reflect.TypeOf(ResultMeta{}), schema, "ResultMeta")
	assertStructMatchesSchema(t, reflect.TypeOf(ProviderTrace{}), schema, "ProviderTrace")
	assertStructMatchesSchema(t, reflect.TypeOf(Capabilities{}), schema, "Capabilities")
	assertStructMatchesSchema(t, reflect.TypeOf(APIError{}), schema, "APIError")
}

func readSchemaDefs(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "packages", "schema", "json", "api-response.schema.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatal(err)
	}
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema is missing $defs")
	}
	defs["APIResponse"] = schema
	return defs
}

func assertStructMatchesSchema(t *testing.T, typ reflect.Type, defs map[string]any, schemaName string) {
	t.Helper()
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	def, ok := defs[schemaName].(map[string]any)
	if !ok {
		t.Fatalf("schema %s not found", schemaName)
	}
	properties, ok := def["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema %s is missing properties", schemaName)
	}
	required := requiredSet(def)
	for _, field := range jsonFields(typ) {
		if _, ok := properties[field.name]; !ok {
			t.Fatalf("%s.%s is missing from schema properties", schemaName, field.name)
		}
		if !field.omitempty && !required[field.name] {
			t.Fatalf("%s.%s is not omitempty but missing from schema required", schemaName, field.name)
		}
	}
}

type jsonField struct {
	name      string
	omitempty bool
}

func jsonFields(typ reflect.Type) []jsonField {
	var fields []jsonField
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := field.Name
		omitempty := false
		if tag != "" {
			parts := strings.Split(tag, ",")
			if parts[0] != "" {
				name = parts[0]
			}
			for _, option := range parts[1:] {
				if option == "omitempty" {
					omitempty = true
				}
			}
		}
		fields = append(fields, jsonField{name: name, omitempty: omitempty})
	}
	return fields
}

func requiredSet(def map[string]any) map[string]bool {
	result := map[string]bool{}
	values, _ := def["required"].([]any)
	for _, value := range values {
		if item, ok := value.(string); ok {
			result[item] = true
		}
	}
	return result
}
