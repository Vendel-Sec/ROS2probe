from collections.abc import Callable
from typing import TypeVar

import pytest

F = TypeVar("F", bound=Callable)


def leaf(leaf_id: str) -> Callable[[F], F]:
    """Tag a test with the attack tree leaf it decides."""

    def decorate(func: F) -> F:
        return pytest.mark.leaf(leaf_id)(func)

    return decorate

