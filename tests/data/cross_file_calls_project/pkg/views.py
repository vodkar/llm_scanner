import pkg.helpers as h
from pkg import helpers
from pkg.base import BaseRepo


class HgRepo(BaseRepo):
    def obtain(self, url):
        self.run(["clone", url])


class LoggedRepo(BaseRepo):
    def run(self, args):
        return super().run(args)


def clean(value):
    return helpers.sanitize(value)


def clean_alias(value):
    return h.sanitize(value)


def related(song, top):
    return song.get_related_songs_json(top)


def count(data):
    return len(data.items())


def log_access(logger, cursor, query):
    logger.info("access")
    return cursor.execute(query)


def shadowed(h, value):
    return h.sanitize(value)
