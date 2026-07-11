import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Awaitable, Optional
from collections import deque

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("GlobalLock")

@dataclass
class TaskRequest:
    task_id: str
    priority: int
    action: Callable[[], Awaitable[Any]]
    callback: Optional[Callable[[Any], Awaitable[None]]] = None

class GlobalLock:
    """
    Ensures only one orchestration task is processed at a time.
    Uses a priority queue to manage requests.
    """
    def __init__(self):
        self._lock = asyncio.Lock()
        self._queue = deque() # Simple queue; for true priority, use heapq or PriorityQueue
        self._processing = False

    async def request_task(self, task_id: str, priority: int, action: Callable[[], Awaitable[Any]], callback=None):
        """
        Queues a task for execution.
        """
        request = TaskRequest(task_id, priority, action, callback)
        self._queue.append(request)
        logger.info(f"Task {task_id} queued. Current queue size: {len(self._queue)}")

        if not self._processing:
            asyncio.create_task(self._process_queue())

    async def _process_queue(self):
        self._processing = True
        while self._queue:
            async with self._lock:
                request = self._queue.popleft()
                logger.info(f"Processing task {request.task_id}...")
                try:
                    result = await request.action()
                    if request.callback:
                        await request.callback(result)
                except Exception as e:
                    logger.error(f"Task {request.task_id} failed: {e}")

        self._processing = False
        logger.info("All tasks processed. Lock released.")
