#include "analyze.h"
#include "audit.h"
#include "collect.h"
#include "db.h"
#include "event.h"
#include "manifest.h"
#include "report.h"
#include "timeline.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "0.3.0"

typedef struct {
    const char *db;
    const char *case_id;
    const char *input;
    const char *image;
    const char *output;
    const char *host;
    const char *conversation;
    const char *from;
    const char *to;
    const char *analysis;
    const char *format;
    const char *reviewer;
    const char *review_status;
    const char *base;
    size_t limit;
    int include_details;
} options;

static void usage(FILE *output) {
    fputs(
        "CEROTTO " VERSION "\n\n"
        "Usage:\n"
        "  cerotto init --db DB\n"
        "  cerotto ingest --db DB --case CASE --input EVENTS.jsonl\n"
        "  cerotto ingest-audit --db DB --case CASE --input AUDIT.log --host HOST\n"
        "  cerotto collect-tsk --db DB --case CASE --image IMAGE --output DIR --host HOST\n"
        "  cerotto collect-ewf --db DB --case CASE --image evidence.E01 --output DIR --host HOST\n"
        "  cerotto timeline --db DB --case CASE --conversation ID [--host HOST] [--from UTC] [--to UTC] [--limit N] [--include-details] [--output FILE]\n"
        "  cerotto analyze --db DB --case CASE --conversation ID [--host HOST] [--from UTC] [--to UTC] [--limit N] [--output FILE]\n"
        "  cerotto manifest --db DB --case CASE [--output FILE]\n"
        "  cerotto verify --db DB --case CASE [--base DIR] [--output FILE]\n"
        "  cerotto report --db DB --case CASE --conversation ID [--analysis FILE] [--format json|markdown] [--reviewer NAME --review-status STATUS] [--output FILE]\n\n"
        "Timestamps must be ISO-8601 UTC, for example 2026-10-27T12:00:00Z.\n"
        "Analysis requires CEROTTO_BASE_URL and CEROTTO_MODEL.\n"
        "The base URL is the OpenAI-compatible prefix before /chat/completions.\n",
        output);
}

static int valid_id(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length;
    if (!value || !value[0]) {
        return 0;
    }
    length = strlen(value);
    if (length > 256) {
        return 0;
    }
    while (*cursor) {
        if (*cursor < 0x20 || *cursor == 0x7f) {
            return 0;
        }
        ++cursor;
    }
    return 1;
}

static int parse_options(int argc, char **argv, options *parsed) {
    int index;
    memset(parsed, 0, sizeof(*parsed));
    parsed->limit = 10000;
    parsed->format = "markdown";
    parsed->review_status = "unreviewed";
    for (index = 0; index < argc; ++index) {
        const char *name = argv[index];
        const char *value = NULL;
        if (strcmp(name, "--include-details") == 0) {
            parsed->include_details = 1;
            continue;
        }
        if (index + 1 >= argc) {
            af_error("missing value for %s", name);
            return -1;
        }
        value = argv[++index];
        if (strcmp(name, "--db") == 0) parsed->db = value;
        else if (strcmp(name, "--case") == 0) parsed->case_id = value;
        else if (strcmp(name, "--input") == 0) parsed->input = value;
        else if (strcmp(name, "--image") == 0) parsed->image = value;
        else if (strcmp(name, "--output") == 0) parsed->output = value;
        else if (strcmp(name, "--host") == 0) parsed->host = value;
        else if (strcmp(name, "--conversation") == 0) parsed->conversation = value;
        else if (strcmp(name, "--from") == 0) parsed->from = value;
        else if (strcmp(name, "--to") == 0) parsed->to = value;
        else if (strcmp(name, "--analysis") == 0) parsed->analysis = value;
        else if (strcmp(name, "--format") == 0) parsed->format = value;
        else if (strcmp(name, "--reviewer") == 0) parsed->reviewer = value;
        else if (strcmp(name, "--review-status") == 0) parsed->review_status = value;
        else if (strcmp(name, "--base") == 0) parsed->base = value;
        else if (strcmp(name, "--limit") == 0) {
            char *end;
            unsigned long limit;
            errno = 0;
            limit = strtoul(value, &end, 10);
            if (errno || *end || end == value || limit == 0 || limit > 10000) {
                af_error("limit must be between 1 and 10000");
                return -1;
            }
            parsed->limit = (size_t)limit;
        } else {
            af_error("unknown option: %s", name);
            return -1;
        }
    }
    if (!parsed->db || (parsed->case_id && !valid_id(parsed->case_id)) ||
        (parsed->host && !valid_id(parsed->host)) ||
        (parsed->conversation && !valid_id(parsed->conversation)) ||
        (parsed->reviewer && !valid_id(parsed->reviewer))) {
        af_error("a database and valid case, host, and conversation identifiers are required");
        return -1;
    }
    return 0;
}

static int open_database(const options *parsed, af_db *db) {
    if (af_db_open(parsed->db, db) != 0) {
        return -1;
    }
    if (af_db_init(db) != 0) {
        af_db_close(db);
        return -1;
    }
    return 0;
}

static int set_source_status(af_db *db, int64_t source_id, const char *status) {
    sqlite3_stmt *statement = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->handle, "UPDATE evidence_sources SET status=?1 WHERE id=?2", -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, source_id);
    if (sqlite3_step(statement) == SQLITE_DONE) {
        result = 0;
    }
    sqlite3_finalize(statement);
    return result;
}

static int command_ingest(const options *parsed, int audit) {
    af_db db;
    af_source source;
    char acquired_at[AF_TIMESTAMP_SIZE];
    char hash[65] = "";
    int64_t size = 0;
    int64_t source_id = 0;
    size_t count = 0;
    int result = -1;
    int ingest_result;
    if (!parsed->case_id || !parsed->input || (audit && !parsed->host)) {
        af_error("%s requires --case and --input%s", audit ? "ingest-audit" : "ingest",
                 audit ? " and --host" : "");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (af_now(acquired_at) != 0 ||
        (strcmp(parsed->input, "-") && (af_sha256_file(parsed->input, hash) || af_file_size(parsed->input, &size)))) {
        af_error("cannot read ingestion source metadata");
        goto cleanup;
    }
    if (af_db_begin(&db) || af_db_ensure_case(&db, parsed->case_id)) {
        goto cleanup;
    }
    memset(&source, 0, sizeof(source));
    source.case_id = parsed->case_id;
    source.kind = audit ? "audit_log" : "agent_jsonl";
    source.origin_path = parsed->input;
    source.stored_path = "";
    source.sha256 = hash;
    source.size_bytes = size;
    source.tool_name = "cerotto";
    source.tool_version = VERSION;
    source.command_json = "[]";
    source.acquired_at = acquired_at;
    source.status = "ingesting";
    source.raw_sha256 = hash;
    if (af_db_insert_source(&db, &source, &source_id) || af_db_commit(&db)) {
        af_db_rollback(&db);
        goto cleanup;
    }
    if (audit) {
        ingest_result = af_ingest_audit(&db, parsed->case_id, parsed->input, parsed->host, source_id, &count);
    } else {
        ingest_result = af_ingest_jsonl(&db, parsed->case_id, parsed->input, source_id, &count);
    }
    if (ingest_result != 0) {
        set_source_status(&db, source_id, "failed");
        goto cleanup;
    }
    if (set_source_status(&db, source_id, "completed") != 0) {
        goto cleanup;
    }
    printf("{\"source_id\":%lld,\"events_ingested\":%zu}\n", (long long)source_id, count);
    result = 0;
cleanup:
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_collect(const options *parsed, int ewf) {
    af_db db;
    size_t count = 0;
    int result;
    if (!parsed->case_id || !parsed->image || !parsed->output || !parsed->host) {
        af_error("%s requires --case, --image, --output, and --host", ewf ? "collect-ewf" : "collect-tsk");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    result = ewf ? af_collect_ewf(&db, parsed->case_id, parsed->image, parsed->output, parsed->host, &count)
                 : af_collect_tsk(&db, parsed->case_id, parsed->image, parsed->output, parsed->host, &count);
    af_db_close(&db);
    if (result == 0) {
        printf("{\"events_collected\":%zu}\n", count);
        return 0;
    }
    return 1;
}

static int prepare_timeline(const options *parsed, af_timeline_query *query,
                            char from[AF_TIMESTAMP_SIZE], char to[AF_TIMESTAMP_SIZE]) {
    memset(query, 0, sizeof(*query));
    if (!parsed->case_id || !parsed->conversation) {
        af_error("timeline, analyze, and report require --case and --conversation");
        return -1;
    }
    if (parsed->from && af_timestamp_normalize(parsed->from, from) != 0) {
        af_error("invalid --from timestamp");
        return -1;
    }
    if (parsed->to && af_timestamp_normalize(parsed->to, to) != 0) {
        af_error("invalid --to timestamp");
        return -1;
    }
    if (parsed->from && parsed->to && strcmp(from, to) >= 0) {
        af_error("--from must be earlier than --to");
        return -1;
    }
    query->case_id = parsed->case_id;
    query->conversation_id = parsed->conversation;
    query->host_id = parsed->host ? parsed->host : "";
    query->from = parsed->from ? from : "";
    query->to = parsed->to ? to : "";
    query->limit = parsed->limit;
    query->metadata_only = !parsed->include_details;
    return 0;
}

static int command_timeline(const options *parsed, int analyze) {
    af_db db;
    af_timeline_query query;
    char from[AF_TIMESTAMP_SIZE];
    char to[AF_TIMESTAMP_SIZE];
    FILE *output = stdout;
    int result;
    if (prepare_timeline(parsed, &query, from, to) != 0) {
        return 1;
    }
    if (analyze) {
        query.metadata_only = 1;
        if (query.limit > 500) {
            query.limit = 500;
        }
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = analyze ? af_analyze(&db, &query, output) : af_timeline_write(&db, &query, output);
    if (output != stdout && fclose(output) != 0) {
        af_error("cannot close output: %s", strerror(errno));
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_case_output(const options *parsed, int verify) {
    af_db db;
    FILE *output = stdout;
    int result;
    if (!parsed->case_id) {
        af_error("%s requires --case", verify ? "verify" : "manifest");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = verify ? af_verify_case(&db, parsed->case_id, parsed->base, output)
                    : af_manifest_write(&db, parsed->case_id, output);
    if (output != stdout && fclose(output) != 0) {
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_report(const options *parsed) {
    af_db db;
    af_timeline_query query;
    char from[AF_TIMESTAMP_SIZE];
    char to[AF_TIMESTAMP_SIZE];
    FILE *output = stdout;
    int result;
    if (prepare_timeline(parsed, &query, from, to) != 0) {
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = af_report_write(&db, &query, parsed->analysis, parsed->format,
                             parsed->reviewer, parsed->review_status, output);
    if (output != stdout && fclose(output) != 0) {
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    options parsed;
    const char *command;
    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        puts(VERSION);
        return 0;
    }
    if (argc < 3 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }
    command = argv[1];
    if (parse_options(argc - 2, argv + 2, &parsed) != 0) {
        return 2;
    }
    if (strcmp(command, "init") == 0) {
        af_db db;
        if (open_database(&parsed, &db) != 0) {
            return 1;
        }
        af_db_close(&db);
        printf("{\"database_initialized\":true,\"schema_version\":%d}\n", AF_SCHEMA_VERSION);
        return 0;
    }
    if (strcmp(command, "ingest") == 0) return command_ingest(&parsed, 0);
    if (strcmp(command, "ingest-audit") == 0) return command_ingest(&parsed, 1);
    if (strcmp(command, "collect-tsk") == 0) return command_collect(&parsed, 0);
    if (strcmp(command, "collect-ewf") == 0) return command_collect(&parsed, 1);
    if (strcmp(command, "timeline") == 0) return command_timeline(&parsed, 0);
    if (strcmp(command, "analyze") == 0) return command_timeline(&parsed, 1);
    if (strcmp(command, "manifest") == 0) return command_case_output(&parsed, 0);
    if (strcmp(command, "verify") == 0) return command_case_output(&parsed, 1);
    if (strcmp(command, "report") == 0) return command_report(&parsed);
    af_error("unknown command: %s", command);
    usage(stderr);
    return 2;
}
