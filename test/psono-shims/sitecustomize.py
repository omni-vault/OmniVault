# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
# Test server only (test/psono-server.sh): the cloud storage SDKs Psono imports (file repositories, avatars) are
# never used by the tested API; they are answered with empty placeholder modules.
import sys, types, importlib.abc, importlib.machinery
STUB = ("google", "azure", "boto3", "botocore", "Cryptodome")
class _Dummy:
    def __init__(self, *a, **k): pass
    def __call__(self, *a, **k): return _Dummy()
    def __getattr__(self, n): return _Dummy()
class _Loader(importlib.abc.Loader):
    def create_module(self, spec):
        m = types.ModuleType(spec.name); m.__path__ = []
        m.__getattr__ = lambda n: _Dummy
        return m
    def exec_module(self, m): pass
class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in STUB:
            return importlib.machinery.ModuleSpec(name, _Loader(), is_package=True)
sys.meta_path.insert(0, _Finder())
