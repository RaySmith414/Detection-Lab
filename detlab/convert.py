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


def _collection(rule: LabRule) -> SigmaCollection:
    # Conversion changes the rule object, so each engine gets its own copy.
    return SigmaCollection([copy.deepcopy(rule.rule)])


def to_eql(rule: LabRule) -> str:
    """EQL for Elasticsearch. EQL string comparisons here ignore case, like Sigma."""
    return _single(EqlBackend(processing_pipeline=ecs_pipeline()).convert(_collection(rule)), rule)


def to_sql(rule: LabRule) -> str:
    """SQL for the SQLite engine the tests use."""
    return _single(sqliteBackend(processing_pipeline=sqlite_pipeline()).convert(_collection(rule)), rule)
