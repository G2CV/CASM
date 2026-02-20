from __future__ import annotations

from setuptools import setup


try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # pragma: no cover - wheel should exist in build env
    _bdist_wheel = None


if _bdist_wheel is None:
    setup()
else:
    class bdist_wheel(_bdist_wheel):
        def finalize_options(self) -> None:
            super().finalize_options()
            self.root_is_pure = False


    setup(cmdclass={"bdist_wheel": bdist_wheel})
