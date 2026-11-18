"""Convert the lab's Sigma rules for the two engines that run them."""

import copy

from sigma.backends.elasticsearch import EqlBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from detlab.pipeline import ecs_pipeline, sqlite_pipeline
from detlab.rules import LabRule


def _single(queries, rule: LabRule) -> str:
    if len(queries) != 1:
        raise ValueError(f"{rule.key}: expected one query, got {len(queries)}")
    return queries[0]


# A threshold rule becomes an EQL sequence. Elasticsearch only chains the events of a sequence
# when it can put them in order. Events that share a timestamp (lines of an auth log within one
# second, a burst within one millisecond) need a second field for that. A search without this
# tiebreaker field misses such a burst.
TIEBREAKER = "event.id"


def _collection(rule: LabRule) -> SigmaCollection:
    # Conversion changes the rule objects, so each engine gets its own copy.
    return copy.deepcopy(rule.collection)


def to_eql(rule: LabRule) -> str:
    """EQL for Elasticsearch. EQL string comparisons here ignore case, like Sigma."""
    return _single(EqlBackend(processing_pipeline=ecs_pipeline()).convert(_collection(rule)), rule)


def to_sql(rule: LabRule) -> str:
    """SQL for the SQLite engine the tests use."""
    return _single(sqliteBackend(processing_pipeline=sqlite_pipeline()).convert(_collection(rule)), rule)
