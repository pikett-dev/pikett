"""The ops-runner: executes approved runbooks on a server.

The modules `catalog` and `jobs` are shared with the ops service, which signs the jobs; they use only the standard
library and `cryptography`, so the runner needs no virtualenv on the server.
"""

__version__ = "0.1"
