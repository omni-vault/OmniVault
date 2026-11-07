# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
# Test server only (test/psono-server.sh): error reporting is not used; every call does nothing.
def __getattr__(name):
    return lambda *a, **k: None
