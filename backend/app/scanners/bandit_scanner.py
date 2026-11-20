from app.scanners.base_scanner import BaseScanner


class BanditScanner(BaseScanner):
    async def scan(self, workspace: str) -> list[dict]:
        return []
