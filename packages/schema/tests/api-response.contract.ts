import type { APIResponse as WebAPIResponse, LookupResult as WebLookupResult } from '@whoice/web-types';
import type { WhoiceAPIResponse, LookupResult as SchemaLookupResult } from '../generated/api-response';

type Assert<T extends true> = T;
type Extends<Left, Right> = [Left] extends [Right] ? true : false;

type EnvelopeFields = 'ok' | 'error' | 'capabilities' | 'meta';

type _WebEnvelopeMatchesSchema = Assert<Extends<Pick<WebAPIResponse, EnvelopeFields>, Pick<WhoiceAPIResponse, EnvelopeFields>>>;
type _SchemaEnvelopeMatchesWeb = Assert<Extends<Pick<WhoiceAPIResponse, EnvelopeFields>, Pick<WebAPIResponse, EnvelopeFields>>>;
type StableResultFields =
  | 'query'
  | 'normalizedQuery'
  | 'type'
  | 'status'
  | 'source'
  | 'domain'
  | 'registry'
  | 'registrar'
  | 'dates'
  | 'statuses'
  | 'nameservers'
  | 'dnssec'
  | 'registrant'
  | 'network'
  | 'raw'
  | 'meta';

type _WebResultStableFieldsMatchSchema = Assert<Extends<Pick<WebLookupResult, StableResultFields>, Pick<SchemaLookupResult, StableResultFields>>>;
type _SchemaResultStableFieldsMatchWeb = Assert<Extends<Pick<SchemaLookupResult, StableResultFields>, Pick<WebLookupResult, StableResultFields>>>;
type _WebEnrichmentKnownFieldsMatchSchema = Assert<Extends<WebLookupResult['enrichment'], Pick<SchemaLookupResult['enrichment'], keyof WebLookupResult['enrichment']>>>;
