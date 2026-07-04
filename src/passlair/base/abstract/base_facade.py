from abc import ABC

from ...dataclasses.facade_result import FacadeResult


class BaseFacade(ABC):
    def _success(self, msg: str, data: dict | None = None) -> FacadeResult:
        data = data or {}
        return FacadeResult(success=True, messege=msg, data=data)

    def _failure(self, msg: str, data: dict | None = None) -> FacadeResult:
        data = data or {}
        return FacadeResult(success=False, messege=msg, data=data)
