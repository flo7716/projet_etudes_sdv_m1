import os

class Settings:

    OPENVAS_HOST = os.getenv("OPENVAS_HOST", "openvas")
    OPENVAS_PORT = int(os.getenv("OPENVAS_PORT", 9390))

    OPENVAS_USERNAME = os.getenv("OPENVAS_USERNAME", "admin")
    OPENVAS_PASSWORD = os.getenv("OPENVAS_PASSWORD", "admin")

settings = Settings()
