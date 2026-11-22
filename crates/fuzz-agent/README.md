# LLM fuzz agent

This is an adversarial, tool-using [Pydantic AI](https://ai.pydantic.dev/) agent for p14g. A language model reads
the repository and submits SQL that tries to escape a fixed policy. Every accepted statement is checked by code
and run on Postgres.

The attacker has one tool, `run_code`, from Pydantic AI Harness's [Code Mode](https://pydantic.dev/docs/ai/harness/):
Python that runs in the [Monty](https://github.com/pydantic/monty) sandbox. From that code it calls `rewrite`, which
runs both inline-literal and parameterized p14g policies, and `report_finding`, and it reads the repository with
`pathlib` at `/library`. One request can read several files, or try a batch of statements in a loop. Its instructions
tell it to start with the project README, `AGENTS.md`, the security-review checklist and `fuzz_agent/target.py`,
which defines the policy and schema it attacks.

`/library` is a read-only mount of `crates/fuzz-agent/.library/`, which each run empties and fills with a fresh copy of
every tracked or unignored file, so the sandbox never sees `.env`, the virtual environment or earlier runs.

The fuzzer needs Python 3.11 or later, for Code Mode.

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
--database-url URL        disposable Postgres server (default: P14G_TEST_DATABASE_URL)
```

Run `uv run --group fuzz-agent python -m fuzz_agent --help` from this directory for the complete CLI.

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
last line survives a process crash. `findings.jsonl` contains the failed checks and anything the agent reported with
`report_finding`, and `notes.md` contains the attacking model's round summaries.

Run the API-free regression tests with `make test-fuzz-agent`. Most need Postgres, as `make test-postgres` does,
and are skipped without `P14G_TEST_DATABASE_URL`.
