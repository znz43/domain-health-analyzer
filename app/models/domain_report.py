from typing import Any

from pydantic import BaseModel, Field


class DomainReport(BaseModel):

    domain: str

    score: float | None = None


    timeline: dict[str, Any] = Field(
        default_factory=dict
    )


    dimensions: dict[str, Any] = Field(
        default_factory=dict
    )


    contexts: list[dict[str, Any]] = Field(
        default_factory=list
    )


    tags: list[str] = Field(
        default_factory=list
    )


    clusters: dict[str, Any] = Field(
        default_factory=dict
    )


    abused: bool = False


    whois: dict[str, Any] = Field(
        default_factory=dict
    )