"""Run the Python examples in README.md and check what they print against their `#>` comments.

`pytest --update-examples` rewrites the output comments from what the examples actually print.

A block marked ```` ```python {test="continue"} ```` runs with the names the block before it defined.
"""

from pathlib import Path
from typing import Any

import pytest
from pytest_examples import CodeExample, EvalExample, find_examples

README = Path(__file__).parents[3] / 'README.md'
EXAMPLES = list(find_examples(README))


def configure(eval_example: EvalExample, example: CodeExample) -> None:
    # a continuation uses names ruff cannot see
    ruff_ignore = ['F821'] if continues(example) else None
    eval_example.set_config(line_length=120, quotes='single', ruff_ignore=ruff_ignore)


def continues(example: CodeExample) -> bool:
    return example.prefix_settings().get('test') == 'continue'


def names_before(example: CodeExample, eval_example: EvalExample) -> dict[str, Any] | None:
    """The globals left by the blocks this one continues, or None if it stands alone."""
    if not continues(example):
        return None
    index = EXAMPLES.index(example)
    assert index > 0, f'{example} continues nothing'
    previous = EXAMPLES[index - 1]
    previous_globals = names_before(previous, eval_example)
    configure(eval_example, previous)
    return eval_example.run(previous, module_globals=previous_globals)


@pytest.mark.parametrize('example', EXAMPLES, ids=str)
def test_readme(example: CodeExample, eval_example: EvalExample):
    module_globals = names_before(example, eval_example)
    configure(eval_example, example)
    if eval_example.update_examples:
        eval_example.format(example)
        eval_example.run_print_update(example, module_globals=module_globals)
    else:
        eval_example.lint(example)
        eval_example.run_print_check(example, module_globals=module_globals)
