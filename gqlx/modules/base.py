"""Abstract base class that every vulnerability module inherits from."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from gqlx.utils.models import ConfidenceLevel, Finding, RunContext, SeverityLevel


@dataclass
class ModuleMetadata:
    name: str
    description: str
    author: str = "gqlx"
    version: str = "1.0.0"
    references: list[str] = field(default_factory=list)
    requires_aggressive: bool = False


class BaseModule(ABC):
    """All vulnerability modules inherit this class and implement ``run()``."""

    metadata: ModuleMetadata  # must be set as a class attribute

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if ABC not in cls.__bases__ and not hasattr(cls, "metadata"):
            raise TypeError(f"{cls.__name__} must define a 'metadata' class attribute")

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def description(self) -> str:
        return self.metadata.description

    @abstractmethod
    async def run(self, ctx: RunContext) -> list[Finding]:
        """Execute the module against the target. Return all discovered findings."""
        ...

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def finding(
        self,
        title: str,
        severity: SeverityLevel,
        description: str,
        endpoint: str,
        evidence: str,
        remediation: str,
        payload: str | None = None,
        references: list[str] | None = None,
        raw_response: str | None = None,
        confidence: ConfidenceLevel = "confirmed",
    ) -> Finding:
        """Convenience factory so modules don't repeat boilerplate.

        ``confidence`` defaults to "confirmed"; heuristic detections that lack a
        confirmation oracle must pass confidence="tentative" so reports can
        separate verified findings from leads that need manual validation.
        """
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            endpoint=endpoint,
            module=self.name,
            payload=payload,
            evidence=evidence,
            remediation=remediation,
            references=references or self.metadata.references,
            raw_response=raw_response,
        )
