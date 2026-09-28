"""Redis client and pubsub coordinator for Autonomous IT Incident Responder.

Publishes normalized LogEvent objects to Redis channel 'raw-logs'.
Includes seamless local fallback queue when Redis server is not reachable,
ensuring offline testing and standalone Windows execution work reliably.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

RAW_LOGS_CHANNEL = "raw-logs"


class RedisClient:
    """Manages connection and publishing to Redis 'raw-logs' channel."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self._redis = None
        self._connected = False
        self._in_memory_subscribers: List[Callable[[Dict[str, Any]], Any]] = []
        self._in_memory_history: List[Dict[str, Any]] = []

    def connect(self) -> bool:
        """Attempt connection to Redis."""
        try:
            import redis
            self._redis = redis.Redis.from_url(
                self.redis_url,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
                decode_responses=True,
            )
            # Ping test
            self._redis.ping()
            self._connected = True
            logger.info("Connected to Redis at %s", self.redis_url)
            return True
        except Exception as e:
            self._connected = False
            self._redis = None
            logger.warning("Redis not available (%s). Using in-memory fallback bus.", e)
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def subscribe_memory(self, callback: Callable[[Dict[str, Any]], Any]) -> None:
        """Register a subscriber callback for in-memory events."""
        self._in_memory_subscribers.append(callback)

    def publish_event(self, event_dict: Dict[str, Any]) -> bool:
        """Publish a normalized LogEvent dictionary to 'raw-logs' channel."""
        # Always record in local history for auditing & test verification
        self._in_memory_history.append(event_dict)

        payload = json.dumps(event_dict)
        published_to_redis = False

        if self._connected and self._redis:
            try:
                self._redis.publish(RAW_LOGS_CHANNEL, payload)
                published_to_redis = True
            except Exception as e:
                logger.warning("Failed to publish to Redis (%s). Falling back.", e)
                self._connected = False

        # Notify in-memory subscribers (e.g. web socket managers, anomaly detector, tests)
        for cb in self._in_memory_subscribers:
            try:
                cb(event_dict)
            except Exception as cb_err:
                logger.error("Error in subscriber callback: %s", cb_err)

        return published_to_redis or True

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._in_memory_history)

    def clear_history(self) -> None:
        self._in_memory_history.clear()


# Global shared instance
default_redis_client = RedisClient()
