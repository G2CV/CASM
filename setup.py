from __future__ import annotations

import platform
import sys

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
            if sys.platform.startswith("linux"):
                machine = platform.machine().lower()
                if machine in {"x86_64", "amd64"}:
                    self.plat_name = "manylinux2014_x86_64"
                elif machine in {"aarch64", "arm64"}:
                    self.plat_name = "manylinux2014_aarch64"

        def get_tag(self):
            # Ship platform-specific wheels that are Python-ABI independent.
            _, _, plat = super().get_tag()
            return "py3", "none", plat


    setup(cmdclass={"bdist_wheel": bdist_wheel})
