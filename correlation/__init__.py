"""Event correlation package (Member 3)."""
from .event_correlator import (
    DEFAULT_TIME_WINDOW_SECONDS,
    correlate_events,
    parse_timestamp,
)

__all__ = ["correlate_events", "parse_timestamp", "DEFAULT_TIME_WINDOW_SECONDS"]