from fastapi import APIRouter

router = APIRouter(prefix="/scans", tags=["reports"])


@router.get("/{scan_id}/report")
async def get_report(scan_id: str):
    return {"success": True, "data": {"scan_id": scan_id, "report": None}}
