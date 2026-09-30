from slowapi import Limiter
from slowapi.util import get_remote_address

# Shared limiter instance used across routers (auth endpoints in particular)
# to blunt credential-stuffing / brute-force attempts. Backed by in-memory
# storage by default, which is sufficient for a single-instance free-tier
# deployment; point it at Redis via storage_uri for multi-instance setups.
limiter = Limiter(key_func=get_remote_address)
