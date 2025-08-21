import subprocess
from pathlib import Path

from pydantic.main import BaseModel


class RemoveCommentsService(BaseModel):
    src: Path

    def remove(self):
        subprocess.run(["shushpy", str(self.src), "--inplace"])
