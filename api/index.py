"""
Vercel serverless entrypoint.

Vercel discovers the HTTP handler by looking for a Python file inside the
repo's api/ directory. The analyzer itself lives one level up so it can be used
as a normal standalone script too; this shim just makes it importable from
within api/.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app import app  # noqa: E402

# Vercel exposes the module's 'app' automatically; exposing it explicitly keeps
# local 'python api/index.py' working too.
if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "5000")), debug=False)