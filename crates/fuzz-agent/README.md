# LLM fuzz agent

This is an adversarial, tool-using [Pydantic AI](https://ai.pydantic.dev/) agent for p14g. A language model reads
the repository and submits SQL that tries to escape a fixed policy. Every accepted statement is checked by code;
an optional second model gives an independent opinion.

The attacker receives the project README, `AGENTS.md`, the security-review checklist and the complete target policy
and schema in its initial instructions. It can then use `list_files`, `search` and `read_file` over every tracked or
unignored text file in the repository. Its `rewrite` tool runs both inline-literal and parameterized p14g policies.

## Run it

Models are reached through the Pydantic AI Gateway and traces go to [Logfire](https://logfire.pydantic.dev/). One
Logfire API key with the `write` and `gateway` permissions does both. Connect this directory to a project and make
the key once:

```bash
cd crates/fuzz-agent
uvx logfire-cli init
uvx logfire-cli api-key write gateway --name p14g-fuzz-agent
```

The key is printed once; keep it in your secret manager. Then start the disposable Postgres container and run one
short round:

```bash
export LOGFIRE_API_KEY=...
make postgres
make fuzz-agent ARGS='--rounds 1 --turns 20'
```

The default attacker is GLM 5.3 on [Doubleword](https://docs.doubleword.ai/inference-api/models), reached through the
Gateway as `gateway/doubleword:zai-org/GLM-5.3`. Any other Doubleword model works the same way, for example
`--model gateway/doubleword:moonshotai/Kimi-K3.1-Pro`, and `--model` takes any other Pydantic AI model name.

`make fuzz-agent` recreates only the `p14g_agent` database inside the server named by
`P14G_TEST_DATABASE_URL`. Do not point it at a server where a database of that name matters. The default points at
the repository's `p14g-test` container on port 54329.

Useful options:

```text
--model MODEL             model that writes attacking SQL
--focus TEXT              use one attack area instead of rotating through the built-in areas
--rounds N                number of independent attack rounds
--turns N                 maximum model requests in each round
--judge-model MODEL       optional independent judge
--judge-threshold P       yes/no cutoff for a decision-model judge
--database-url URL        disposable Postgres server; omit it when invoking Python directly for static checks only
```

Run `uv run --group fuzz-agent python -m fuzz_agent --help` from this directory for the complete CLI.

## JEV judge

[JEV](https://typesafe.ai/blog/introducing-system-one-models-and-jev) is a System One model: it answers typed
questions with probabilities instead of generating text. That makes it suitable as a cheap second opinion on each
accepted rewrite, while a generative model remains responsible for producing the SQL. Pydantic AI exposes JEV as a
decision model and maps the fields in `judge.Verdict` to parallel yes/no questions.

Set `TYPESAFE_API_KEY` and the runner automatically uses `typesafe:jev-latest`:

```bash
export TYPESAFE_API_KEY=...
make fuzz-agent ARGS='--rounds 1'
```

For repeatable evaluation, pass a versioned model after tuning the threshold, for example
`--judge-model typesafe:jev-1.13.0`. `jev-latest` is a moving alias, so its answer distribution can change. Judge
flags are recorded as opinions and do not make the command fail. The attacking model is not shown them, which keeps
it from optimizing against the judge. Findings record the exact model version returned by the provider even when
the configured name is an alias.

## Traces

Each run is one trace: a span for the run, one for each round, and under those the model requests and tool calls
that Pydantic AI records. Every `rewrite` call has an `attempt` span with the statement, whether it was accepted,
the output, the rejection and what Postgres did. Under it are spans for the rewrite in each literal mode, the
structure check, the `EXPLAIN` as the restricted role and the run as the owner, along with the statements psycopg
sent. Every finding is also a warning-level log, so `level >= warn` in Logfire lists them.

## Checks

The deterministic oracle:

- parses emitted SQL with Postgres's parser and rejects extra statements, tables and functions;
- rewrites emitted SQL again to check stability where filters and insert extras permit it;
- asks Postgres to plan the output as a role granted only what the policy allows;
- executes it as the owner inside a rolled-back transaction, then looks for randomized canaries in rows and errors;
- compares every table before and after execution to find forbidden inserts, updates and deletes;
- checks row limits, panics, slow rewrites, and agreement between inline and parameterized literal modes.

Runs are written under `crates/fuzz-agent/runs/`. `attempts.jsonl` is written before p14g sees a statement, so its
last line survives a process crash. `findings.jsonl` contains deterministic failures and model opinions, and
`notes.md` contains the attacking model's round summaries.

Run the API-free regression tests with `make test-fuzz-agent`.
