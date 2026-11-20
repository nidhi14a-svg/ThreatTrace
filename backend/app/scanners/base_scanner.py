from abc import ABC, abstractmethod


class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, workspace: str) -> list[dict]:
        """Execute a scanner against an isolated workspace and return normalized findings."""
        raise NotImplementedError
