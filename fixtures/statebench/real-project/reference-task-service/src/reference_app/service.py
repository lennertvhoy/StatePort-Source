"""Service boundary awaiting durable task creation."""


class TaskService:
    def create_task(self, payload: object) -> object:
        raise RuntimeError("durable task creation is unavailable")
