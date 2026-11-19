// The wire constants of the security-monitoring export (spec/siem-export/SPEC.md): what an install sends to
// the customer's collector, and how often. They are the public specification's, so they live here: the
// specification generator reads its constants table from this file, and the engine's exporter imports the
// same values.

/** The two streams an install can export: what the detectors and signals raise, and the audit log's rows. */
export const SIEM_STREAMS = ['security', 'audit'] as const;
export type SiemStream = (typeof SIEM_STREAMS)[number];

/** How serious a record is, as the export says it. */
export const SIEM_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type SiemSeverity = (typeof SIEM_SEVERITIES)[number];

/** Syslog facility 4, security/authorization messages (RFC 5424 section 6.2.1). */
export const SIEM_SYSLOG_FACILITY = 4;
/** The syslog severity each record severity is sent as (RFC 5424 section 6.2.1: 2 critical, 4 warning, 6 informational). */
export const SIEM_SYSLOG_SEVERITY: Record<SiemSeverity, number> = { critical: 2, warning: 4, info: 6 };
/** The SD-ID of the one structured-data element of every syslog message. */
export const SIEM_SYSLOG_SD_ID = 'stack@32473';
/** The APP-NAME of every syslog message. */
export const SIEM_SYSLOG_APP_NAME = 'stack-engine';
/** The HOSTNAME of every syslog message. */
export const SIEM_SYSLOG_HOSTNAME = 'stack';
/** One syslog message is at most this many bytes: a record that would make it longer is sent without its detail. */
export const SIEM_SYSLOG_MAX_BYTES = 8_000;

/** The content type of a batch sent to an HTTPS collector. */
export const SIEM_HTTP_CONTENT_TYPE = 'application/x-ndjson';
/** How many records one batch holds at most, and so how many one HTTPS request or one stream connection carries. */
export const SIEM_BATCH_SIZE = 200;
/** A record newer than this is left for the next pass, so that a transaction that committed late is not skipped. */
export const SIEM_SETTLE_SECONDS = 5;
/** How often the exporter looks for new records. */
export const SIEM_PASS_INTERVAL_SECONDS = 5;
/** How long one connection or request to a collector may take. */
export const SIEM_SINK_TIMEOUT_SECONDS = 10;
/** How long one machine holds a stream before another may take it. */
export const SIEM_LOCK_SECONDS = 30;
/** The default port of a syslog collector over UDP and TCP, and over TLS (RFC 5426, RFC 6587, RFC 5425). */
export const SIEM_DEFAULT_SYSLOG_PORT = 514;
export const SIEM_DEFAULT_SYSLOG_TLS_PORT = 6514;
