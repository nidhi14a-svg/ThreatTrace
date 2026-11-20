from fastapi import APIRouter, UploadFile, File

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
async def create_scan(file: UploadFile = File(...)):
    return {"success": True, "data": {"scan_id": "pending", "status": "accepted"}, "message": "Scan upload received"}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    return {"success": True, "data": {"scan_id": scan_id, "status": "pending"}}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    return {"success": True, "data": {"scan_id": scan_id}, "message": "Scan deleted"}
