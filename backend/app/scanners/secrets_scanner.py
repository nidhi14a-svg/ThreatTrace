from app.scanners.base_scanner import BaseScanner


class SecretsScanner(BaseScanner):
    async def scan(self, workspace: str) -> list[dict]:
        return []
