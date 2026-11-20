from fastapi import APIRouter

router = APIRouter(prefix="/scans", tags=["findings"])


@router.get("/{scan_id}/findings")
async def list_findings(scan_id: str):
    return {"success": True, "data": {"scan_id": scan_id, "findings": []}}
