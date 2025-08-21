import subprocess
from pathlib import Path

from pydantic import BaseModel


class FormattingService(BaseModel):
    src: Path

    def format(self):
        # Runs black formatting on the source code
        subprocess.run(["black", str(self.src)])
