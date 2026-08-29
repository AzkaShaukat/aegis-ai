from loguru import logger
import sys

# Remove default handler
logger.remove()

# 1. Terminal Output (Colorful, for development)
logger.add(
    sys.stdout,
    colorize=True,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
)

# 2. File Output (JSON format, for "Enterprise" auditing)
logger.add(
    "app/aegis_logs.json",    rotation="10 MB",
    retention="10 days",
    serialize=True  # Saves as structured JSON
)

log = logger