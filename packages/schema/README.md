# Schema

This package holds the public API contract for Whoice.

- `openapi.yaml`: HTTP endpoints and component schemas.
- `json/api-response.schema.json`: JSON Schema for the shared response envelope.

The Go model is still the source of truth during the MVP, but the schema package now has contract checks to catch drift.

Run `pnpm test:schema` from the repository root to:

- validate OpenAPI and JSON Schema syntax
- validate curated API response samples against JSON Schema
- regenerate `generated/api-response.d.ts` from JSON Schema
- type-check Web API types against the generated schema types

Go model field coverage is checked by `services/lookup-api/internal/model/schema_contract_test.go`.
