//! The functions allowed by default.
//!
//! A function is in the default set only if it has no side effects, reads nothing but its arguments, and
//! cannot be made to allocate or compute far more than the size of its inputs. Matching is by name, so
//! every overload of a listed name is allowed.
//!
//! Deliberately left out:
//!
//! * `repeat`, `lpad`, `rpad`, `format`: a length or pattern from the query lets one call allocate gigabytes.
//! * `regexp_*`: regular expressions can be made very slow.
//! * `generate_series`, `unnest`, `jsonb_array_elements`, `regexp_split_to_table`: set-returning, they multiply rows.
//! * `version`, `current_user`, `session_user`, `current_setting`, `current_database`, `inet_server_addr`:
//!   server and session information.
//! * `set_config`, `nextval`, `setval`, `pg_sleep`, `pg_advisory_lock`, `pg_notify`, `setseed`: side effects.
//! * everything else prefixed `pg_`, `lo_*`, `dblink*`, `query_to_xml`, `to_regclass`: files, catalogs and
//!   other databases.
//! * `to_json`, `to_jsonb`, `row_to_json`, `jsonb_build_object`: harmless while whole-row references cannot
//!   be written, kept out until that has had more testing.
//!
//! One listed name is weaker than the rule above: `substring(text, text)` is a regular expression match.

pub const AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "bool_and",
    "bool_or",
    "every",
    "string_agg",
    "array_agg",
    "stddev",
    "variance",
];

pub const WINDOW: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
];

pub const CONDITIONAL: &[&str] = &["coalesce", "nullif", "greatest", "least"];

pub const TEXT: &[&str] = &[
    "lower",
    "upper",
    "length",
    "char_length",
    "trim",
    "ltrim",
    "rtrim",
    "btrim",
    "substring",
    "substr",
    "left",
    "right",
    "position",
    "strpos",
    "replace",
    "concat",
    "concat_ws",
    "starts_with",
    "split_part",
    "initcap",
    "reverse",
    "md5",
];

pub const MATHS: &[&str] = &[
    "abs", "round", "ceil", "ceiling", "floor", "trunc", "mod", "power", "sqrt", "sign", "ln", "log", "exp", "random",
];

pub const DATETIME: &[&str] = &[
    "now",
    "current_date",
    "current_timestamp",
    "date_trunc",
    "date_part",
    "extract",
    "age",
    "to_char",
    "to_date",
    "to_timestamp",
    "make_date",
];

pub const JSON: &[&str] = &[
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_array_length",
    "jsonb_typeof",
    "json_extract_path",
    "json_extract_path_text",
    "json_array_length",
    "json_typeof",
];

pub const ARRAYS: &[&str] = &["array_length", "cardinality", "array_position"];

pub const OTHER: &[&str] = &["gen_random_uuid"];

/// Functions no policy can allow, in `functions` or in a rule's `filter`, in any schema.
///
/// Each can change the role a statement runs as: `set_config` sets `role` and `session_authorization`, the
/// others run SQL given as text, which can call it. Postgres 18 has no other built-in function that does either.
/// The `dblink` functions are from an extension, and connect as whoever their connection string names.
pub const FORBIDDEN: &[&str] = &[
    "set_config",
    "query_to_xml",
    "query_to_xml_and_xmlschema",
    "ts_stat",
    "ts_rewrite",
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_open",
    "dblink_send_query",
];

/// Whether `name`, without its schema, is in [`FORBIDDEN`].
#[must_use]
pub fn is_forbidden(name: &str) -> bool {
    FORBIDDEN.contains(&name)
}

/// Every group that makes up the default set.
pub const DEFAULT_GROUPS: &[&[&str]] = &[
    AGGREGATES,
    WINDOW,
    CONDITIONAL,
    TEXT,
    MATHS,
    DATETIME,
    JSON,
    ARRAYS,
    OTHER,
];

/// All the functions allowed when `default_functions` is on.
pub fn defaults() -> impl Iterator<Item = &'static str> {
    DEFAULT_GROUPS.iter().flat_map(|group| group.iter().copied())
}

/// Whether `name` is one of the built-in defaults, which are written qualified with `pg_catalog`.
#[must_use]
pub fn is_default(name: &str) -> bool {
    defaults().any(|n| n == name)
}
