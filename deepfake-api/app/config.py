from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

class Settings(BaseSettings):
    # Image pipeline
    IMAGE_EFFICIENTNET_PATH: str = "app/models/efficientnet_best.pth"
    IMAGE_VIT_PATH: str          = "app/models/vit_best.pth"
    IMAGE_FREQCNN_PATH: str      = "app/models/freqcnn_best.pth"
    IMAGE_ENSEMBLE_CONFIG: str   = "app/models/ensemble_config.json"

    # Video pipeline
    VIDEO_SPATIAL_PATH: str    = "app/models/spatial_best.pth"
    VIDEO_TEMPORAL_PATH: str   = "app/models/temporal_best.pth"
    VIDEO_FREQ_SRM_PATH: str   = "app/models/freq_srm_best.pth"
    VIDEO_ENSEMBLE_CONFIG: str = "app/models/ensemble_video_config.json"

    DEVICE: str = "auto"

    # Image processing
    IMAGE_SIZE: int     = 224
    IMAGENET_MEAN: list = [0.485, 0.456, 0.406]
    IMAGENET_STD: list  = [0.229, 0.224, 0.225]

    # Quality gate
    MIN_FACE_SIZE_PX: int      = 60
    MIN_BLUR_SCORE: float      = 20.0
    MIN_FACE_VISIBILITY: float = 0.30

    # Video — unlimited, 1 fps for speed
    VIDEO_FPS_EXTRACT: int      = 1
    SEQUENCE_LENGTH: int        = 16
    MAX_VIDEO_SIZE_MB: int      = 99999   # effectively unlimited
    MAX_VIDEO_DURATION_SEC: int = 3600
    MAX_IMAGE_SIZE_MB: int      = 50      # 50 MB per image

    # API
    API_KEY: str          = ""
    PORT: int             = 8004
    LOG_LEVEL: str        = "INFO"
    HTTP_TIMEOUT: float   = 30.0
    RATE_LIMIT_ENABLED: bool = True

    # Redis
    REDIS_URL: str         = "redis://aegis_deepfake_redis:6379/0"
    CACHE_TTL_SECONDS: int = 3600
    JOB_TTL_SECONDS: int   = 3600

    # Ensemble weights
    IMAGE_DEFAULT_WEIGHTS: list = [0.50, 0.45, 0.05]
    VIDEO_DEFAULT_WEIGHTS: list = [0.45, 0.20, 0.35]

    # Risk thresholds
    RISK_CLEAN_MAX: int  = 15
    RISK_LOW_MAX: int    = 35
    RISK_MEDIUM_MAX: int = 55
    RISK_HIGH_MAX: int   = 75

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
