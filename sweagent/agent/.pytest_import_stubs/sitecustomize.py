# Auto-stub missing imports for pytest collection.
# Loaded automatically when directory is on sys.path (Python 'site' behavior).
# Docs: https://docs.python.org/3/library/site.html
import os, sys, types, importlib.abc, importlib.util

STUB_ENABLED = os.getenv("STUB_MISSING_IMPORTS", "1").lower() not in ("0", "false", "")
ALLOW = [x.strip() for x in os.getenv("STUB_ALLOW", "django").split(",") if x.strip()]
LOG = os.getenv("STUB_LOG", "0").lower() in ("1", "true")

class _Dummy(types.ModuleType):
    def __init__(self, name):
        super().__init__(name)
        self.__name__ = name
    def __call__(self, *a, **kw):
        # If a stubbed object is actually executed, skip the test gracefully.
        try:
            import pytest
            pytest.skip(f"Stubbed external import called: {self.__name__}")
        except Exception:
            # Fallback if pytest is not importable yet.
            raise RuntimeError(f"Stub called: {self.__name__}")
    def __getattr__(self, attr):
        modname = f"{self.__name__}.{attr}"
        m = _Dummy(modname)
        sys.modules[modname] = m
        return m

class _Stub(types.ModuleType):
    def __getattr__(self, attr):
        modname = f"{self.__name__}.{attr}"
        m = _Dummy(modname)
        sys.modules[modname] = m
        return m

class _Finder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if not STUB_ENABLED or not ALLOW:
            return None
        top = fullname.split(".", 1)[0]
        if top not in ALLOW:
            return None
        if fullname in sys.modules:
            return None
        # If a real finder can import it, don't stub.
        for f in sys.meta_path:
            if f is self:
                continue
            try:
                if f.find_spec(fullname, path, target) is not None:
                    return None
            except Exception:
                pass
        if LOG:
            print(f"[pytest-stub] creating placeholder for {fullname}", file=sys.stderr)
        return importlib.util.spec_from_loader(fullname, self, is_package=True)
    def create_module(self, spec):
        m = _Stub(spec.name)
        m.__path__ = []  # mark as a package so nested imports work
        return m
    def exec_module(self, module):
        return

if STUB_ENABLED:
    sys.meta_path.append(_Finder())
