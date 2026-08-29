from loguru import logger
import sys

# Remove the default logger so we can configure our own
logger.remove()

# 1. Console Output (Human readable colors)
logger.add(
    sys.stdout,
    colorize=True,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
)

# 2. File Output (Machine readable JSON)
# This creates a permanent record of every scan
logger.add(
    "app/qr_logs.json",
    rotation="10 MB",
    retention="10 days",
    serialize=True 
)

log = logger