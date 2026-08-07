from pydantic import BaseModel
from typing import Any


class DomainReport(BaseModel):

    #
    # Domain name
    #
    domain: str


    #
    # Spamhaus reputation score
    #
    score: float | None = None


    #
    # Listing timeline
    #
    timeline: dict[str, Any]


    #
    # Reputation dimensions
    #
    dimensions: dict[str, Any]


    #
    # Spamhaus contexts
    #
    contexts: list[dict[str, Any]]


    #
    # Domain metadata
    #
    tags: list[str] = []

    clusters: dict[str, Any] = {}