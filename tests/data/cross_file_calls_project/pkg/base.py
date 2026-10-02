import subprocess


class BaseRepo:
    def run(self, args):
        return subprocess.check_output(["hg", *args])
