from typing import TypeVar, cast, override

_T = TypeVar("_T")


class SingletonMeta(type):
    _instances: dict[type, object] = {}

    @override
    def __call__(cls: type[_T], *args: object, **kwargs: object) -> _T:
        if cls not in SingletonMeta._instances:
            instance: _T = cast(_T, super().__call__(*args, **kwargs))
            SingletonMeta._instances[cls] = instance
        return cast(_T, SingletonMeta._instances[cls])
