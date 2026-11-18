"""pySigma processing pipelines built from detlab.fields."""

from collections.abc import Callable

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation

from detlab.fields import FIELD_MAP, LOGSOURCES, flat


def _build(name: str, rename: Callable[[str], str]) -> ProcessingPipeline:
    items = [
        ProcessingItem(
            identifier=f"lab_logsource_{product}_{category}",
            transformation=AddConditionTransformation({rename(field): value for field, value in conditions.items()}),
            rule_conditions=[LogsourceCondition(product=product, category=category)],
        )
        for (product, category), conditions in LOGSOURCES.items()
    ]
    items.append(ProcessingItem(
        identifier="lab_field_mapping",
        transformation=FieldMappingTransformation({field: rename(target) for field, target in FIELD_MAP.items()}),
    ))
    return ProcessingPipeline(name=name, priority=50, items=items)


def ecs_pipeline() -> ProcessingPipeline:
    """Sigma fields to ECS fields, for Elasticsearch."""
    return _build("Detection Lab ECS mapping", lambda field: field)


def sqlite_pipeline() -> ProcessingPipeline:
    """The same mapping with flat column names, for the SQLite test engine."""
    return _build("Detection Lab flat mapping", flat)
