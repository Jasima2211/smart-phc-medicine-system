import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-smart-phc-secret-key-hackathon-2026-safe-random-phrase")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "instance", "phc.db"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    # Stock Risk Threshold Multipliers & Defaults
    DEFAULT_LEAD_TIME_DAYS = 7
    # Threshold rules:
    # CRITICAL: days_remaining <= lead_time OR usable_stock == 0 OR days_remaining <= 3
    # HIGH: days_remaining <= lead_time * 1.5
    # MEDIUM: days_remaining <= lead_time * 2.2 OR usable_stock < safety_stock
    # SAFE: surplus above medium threshold

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    DATABASE_PATH = ":memory:"
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
