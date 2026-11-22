import os
from collections.abc import Iterator

import logfire
import pytest
from fuzz_agent.oracle import Oracle

# spans are made but go nowhere; without this, logfire warns on the first one and the warning is an error
logfire.configure(send_to_logfire=False, console=False)


@pytest.fixture
def database_url() -> str:
    """A throwaway Postgres, as for `make test-postgres`; the tests that need one are skipped without it."""
    url = os.environ.get('P14G_TEST_DATABASE_URL')
    if not url:
        pytest.skip('P14G_TEST_DATABASE_URL is not set; `make postgres` starts a database')
    return url


@pytest.fixture
def oracle(database_url: str) -> Iterator[Oracle]:
    oracle = Oracle(database_url)
    yield oracle
    oracle.close()
