from collections.abc import Callable, Iterable


def get_engine_classes(name: str, platform: str) -> tuple[type, ...]:
    if name != "tun":
        return ()

    from .engines.tun import TUNEngine
    from .engines.xray import XRayEngine

    if platform == "win32":
        from .engines.sni import SNIEngine

        return SNIEngine, XRayEngine, TUNEngine
    if platform.startswith("linux"):
        return XRayEngine, TUNEngine
    return ()


def stop_engines_in_reverse(engines: Iterable[object]) -> None:
    for engine in reversed(tuple(engines)):
        try:
            engine.stop()
        except Exception:
            pass


def start_engines_in_order(
    engines: Iterable[object],
    start_engine: Callable[[object], bool] | None = None,
) -> list[object]:
    started = []
    start = start_engine or (lambda engine: engine.start())

    try:
        for engine in engines:
            if not start(engine):
                stop_engines_in_reverse(started)
                return []
            started.append(engine)
    except Exception:
        stop_engines_in_reverse(started)
        raise

    return started
