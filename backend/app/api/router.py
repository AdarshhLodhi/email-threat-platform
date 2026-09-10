from fastapi import APIRouter
from .email import router as email_router
from .cases import router as cases_router
from .reports import router as reports_router
from .dashboard import router as dashboard_router
from .correlation import router as correlation_router
from .intel import router as intel_router
from .steganography import router as steganography_router
from .origin_attribution import router as origin_attribution_router

api_router = APIRouter()
api_router.include_router(email_router, prefix="/email", tags=["Email Processing"])
api_router.include_router(cases_router, prefix="/cases", tags=["Case Management"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(correlation_router, prefix="/correlation", tags=["Infrastructure Correlation"])
api_router.include_router(intel_router, prefix="/intel", tags=["Threat Intelligence"])
api_router.include_router(steganography_router, prefix="/steganography", tags=["Steganography & Attachments"])
api_router.include_router(origin_attribution_router, prefix="/origin-attribution", tags=["Origin Intelligence & Attribution"])
