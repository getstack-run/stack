// The options the API's HTTP server is created with.

import type { ServerOptions } from 'node:http';
import { HTTP_MAX_HEADER_BYTES } from '@stack/shared';

/** Request headers up to HTTP_MAX_HEADER_BYTES: a Passport in a header may be up to PASSPORT_TOKEN_MAX_CHARS long. */
export const API_HTTP_OPTIONS: ServerOptions = { maxHeaderSize: HTTP_MAX_HEADER_BYTES };
