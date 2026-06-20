from abc import ABC
from typing import Any

from ...dataclasses.facade_result import FacadeResult


class BaseFacade(ABC):
    def _success(self, msg: str, data: Any = None) -> FacadeResult:
        return FacadeResult(success=True, messege=msg, data=data)

    def _failure(self, msg: str, data: Any = None) -> FacadeResult:
        return FacadeResult(success=False, messege=msg, data=data)
