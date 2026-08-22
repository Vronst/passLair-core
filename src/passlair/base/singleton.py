from typing import TypeVar, cast, override

_T = TypeVar("_T")


class SingletonMeta(type):
    _instances: dict[type, object] = {}

    @override
    def __call__(cls: type[_T], *args: object, **kwargs: object) -> _T:
        if cls not in SingletonMeta._instances:
            # Not super().__call__(...): mypy can't statically prove a
            # type[_T]-annotated cls is "an instance of" SingletonMeta for
            # zero-arg super() to resolve against (a known limitation for
            # generic-singleton-metaclass __call__ overrides), even though
            # it always is at runtime. SingletonMeta's only base is type, so
            # calling type.__call__ directly is equivalent and sidesteps it.
            instance: _T = cast(_T, type.__call__(cls, *args, **kwargs))
            SingletonMeta._instances[cls] = instance
        return cast(_T, SingletonMeta._instances[cls])
