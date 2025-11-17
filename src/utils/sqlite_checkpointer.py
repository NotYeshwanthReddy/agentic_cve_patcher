"""SQLite-based checkpointer for state persistence."""
import os
import sqlite3
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Database path - store in data directory
DB_DIR = os.getenv("DB_DIR", "data")
DB_PATH = os.path.join(DB_DIR, "checkpoints.db")
print(f"DB_DIR: {DB_DIR}, DB_PATH: {DB_PATH}")

# Singleton checkpointer instance
_checkpointer = None


def get_checkpointer():
    """Get or create SQLite checkpointer instance."""
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer
    
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        logger.info(f"Initializing SQLite checkpointer using langgraph.checkpoint.sqlite at: {DB_PATH}")
        os.makedirs(DB_DIR, exist_ok=True)
        
        # Create SQLite connection and use it directly
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _checkpointer = SqliteSaver(conn)
        return _checkpointer
    except ImportError:
        # If neither works, use MemorySaver as fallback
        logger.warning("SQLite checkpointer not available, using MemorySaver")
        from langgraph.checkpoint.memory import MemorySaver
        _checkpointer = MemorySaver()
        return _checkpointer
