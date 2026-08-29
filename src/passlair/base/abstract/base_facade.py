from abc import ABC
from collections.abc import Mapping

from ...dataclasses.facade_result import FacadeResult


class BaseFacade(ABC):
    def _success(
        self, msg: str, data: Mapping[str, object] | None = None
    ) -> FacadeResult:
        data = data or {}
        return FacadeResult(success=True, message=msg, data=data)

    def _failure(
        self, msg: str, data: Mapping[str, object] | None = None
    ) -> FacadeResult:
        data = data or {}
        return FacadeResult(success=False, message=msg, data=data)
