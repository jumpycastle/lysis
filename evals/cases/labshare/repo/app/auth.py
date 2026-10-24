from functools import wraps
from flask import request, g, abort
from .oidc import verify_access_token


def require_token(fn):
    @wraps(fn)
    def inner(*a, **kw):
        hdr = request.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            abort(401)
        g.user = verify_access_token(hdr[7:])  # validates signature, issuer, audience, expiry
        return fn(*a, **kw)
    return inner


def require_role(role):
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if g.user.get("role") != role:
                abort(403)
            return fn(*a, **kw)
        return inner
    return deco
