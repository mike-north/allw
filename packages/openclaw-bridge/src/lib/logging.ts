/**
 * Structured operator logging that **never emits approval plaintext**.
 *
 * The bridge sits on the plaintext side of the E2EE boundary: it holds the command text, cwd, and
 * summary the human is shown. A log line is not an encrypted channel, so the logger's field
 * allowlist is a security control, not a formatting preference — the fields below are ids, reason
 * codes, counts, and timings only. Anything carrying user content (`commandText`, `cwd`, `summary`,
 * `argv`, plugin prose, device tokens) must never be passed here.
 *
 * @see ../../../../docs/openclaw-integration.md §6.5 Structure-not-data, §12 slice 6
 * @see ../../../../docs/threat-model.md
 */

/** Severity levels the bridge emits. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** The only value types a log field may carry — no objects, so nested plaintext cannot slip in. */
export type LogValue = string | number | boolean | null;

/** A structured log record. `event` is a stable, greppable code. */
export interface LogRecord {
  readonly level: LogLevel;
  readonly event: string;
  readonly fields: Readonly<Record<string, LogValue>>;
}

/** Sink for structured records; production writes NDJSON to stderr. */
export type LogSink = (record: LogRecord) => void;

/** The bridge logger surface. */
export interface Logger {
  debug(event: string, fields?: Readonly<Record<string, LogValue>>): void;
  info(event: string, fields?: Readonly<Record<string, LogValue>>): void;
  warn(event: string, fields?: Readonly<Record<string, LogValue>>): void;
  error(event: string, fields?: Readonly<Record<string, LogValue>>): void;
}

/** Build a logger over a sink. */
export function createLogger(sink: LogSink): Logger {
  const emit =
    (level: LogLevel) =>
    (event: string, fields: Readonly<Record<string, LogValue>> = {}): void => {
      sink({ level, event, fields });
    };
  return {
    debug: emit("debug"),
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
  };
}

/** NDJSON-to-stderr sink. stdout is left clean for future machine-readable output. */
export function stderrSink(record: LogRecord): void {
  process.stderr.write(
    `${JSON.stringify({ level: record.level, event: record.event, ...record.fields })}\n`,
  );
}

/** A logger that discards everything (tests that assert on behavior, not output). */
export const silentLogger: Logger = createLogger(() => undefined);
