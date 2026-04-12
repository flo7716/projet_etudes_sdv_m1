from abc import ABC, abstractmethod
from datetime import datetime


class BaseModule(ABC):

    def __init__(self, target: str):
        self.target = target
        self.start_time = None
        self.end_time = None

    def run(self):
        self.start_time = datetime.now()

        result = self.execute()

        self.end_time = datetime.now()

        return {
            "module": self.__class__.__name__,
            "target": self.target,
            "start_time": str(self.start_time),
            "end_time": str(self.end_time),
            "result": result
        }

    @abstractmethod
    def execute(self):
        pass