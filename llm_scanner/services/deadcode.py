import subprocess
from pathlib import Path

from pydantic.main import BaseModel


class DeadCodeService(BaseModel):
    src: Path

    def remove(self):
        # Runs dead code detection on the source code
        subprocess.run(["deadcode", str(self.src)])
