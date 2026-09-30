import os
import sys
import secrets
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "SecureMailScope"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")  # "development" | "production"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./securemailscope.db")
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "250"))
    MAX_PACKETS_PER_CAPTURE: int = int(os.getenv("MAX_PACKETS_PER_CAPTURE", "500000"))
    ANALYSIS_TIMEOUT_SECONDS: int = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "300"))
    # Comma-separated string, e.g. "https://securemailscope.ntro.gov.in" or
    # "https://a.example,https://b.example". Deliberately typed as a plain
    # str field (not list) because pydantic-settings JSON-decodes env
    # values for list-typed fields, which crashes on ordinary
    # comma-separated ops config -- the natural way to set this in a .env
    # file or container environment. Use the `CORS_ORIGINS` property below
    # to get the parsed list. No wildcard default: an unset value in
    # production is a misconfiguration, not a convenience, since
    # allow_credentials=True combined with allow_origins=["*"] effectively
    # allows any site to make authenticated requests on a logged-in user's
    # behalf.
    CORS_ORIGINS_RAW: str = Field(default="", validation_alias="CORS_ORIGINS")
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    LOGIN_RATE_LIMIT: str = "10/minute"

    @property
    def CORS_ORIGINS(self) -> list:
        return [o.strip() for o in self.CORS_ORIGINS_RAW.split(",") if o.strip()]

    @CORS_ORIGINS.setter
    def CORS_ORIGINS(self, value):
        # Allows the dev-convenience fallback below to still write
        # `settings.CORS_ORIGINS = ["*"]` naturally.
        self.CORS_ORIGINS_RAW = ",".join(value) if isinstance(value, (list, tuple)) else str(value)

    class Config:
        env_file = ".env"


settings = Settings()

if settings.ENVIRONMENT == "production":
    if not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32:
        sys.exit(
            "FATAL: SECRET_KEY must be set to a random value of at least 32 characters "
            "when ENVIRONMENT=production (generate one with: python -c "
            "\"import secrets; print(secrets.token_urlsafe(48))\"). Refusing to start "
            "with a missing/weak secret, since it would let anyone forge auth tokens."
        )
    if not settings.CORS_ORIGINS:
        sys.exit(
            "FATAL: CORS_ORIGINS must be set to your deployed frontend origin(s) when "
            "ENVIRONMENT=production (comma-separated). Refusing to start with an open "
            "or unset CORS policy on a production deployment."
        )
    if settings.DATABASE_URL.startswith("sqlite"):
        print(
            "WARNING: DATABASE_URL is sqlite in ENVIRONMENT=production. SQLite has no "
            "concurrent-writer story suitable for multi-worker/multi-instance production "
            "deployment -- point DATABASE_URL at PostgreSQL before scaling past one "
            "single-threaded worker (see docker-compose.yml's postgres profile).",
            file=sys.stderr,
        )
elif not settings.SECRET_KEY:
    # Development convenience only: an ephemeral random key so local runs
    # don't need a .env file, but tokens won't survive a process restart.
    settings.SECRET_KEY = secrets.token_urlsafe(48)
    print("NOTE: no SECRET_KEY set -- using a random ephemeral key for this dev run "
          "(existing sessions will invalidate on restart). Set SECRET_KEY in .env "
          "for a stable dev key, and always set it explicitly in production.")
    if not settings.CORS_ORIGINS:
        settings.CORS_ORIGINS = ["*"]  # dev-only convenience, never used in production (see above)

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
