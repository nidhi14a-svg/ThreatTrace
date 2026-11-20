from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongodb_uri: str = "mongodb://mongodb:27017"
    database_name: str = "thread_trace"
    backend_port: int = 8000
    upload_directory: str = "/tmp/thread-trace/uploads"
    max_upload_size: int = 104857600
    ai_api_key: str | None = None
    ai_model: str | None = None


settings = Settings()
