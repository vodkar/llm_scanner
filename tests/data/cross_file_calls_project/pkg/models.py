class Song:
    def get_related_songs_json(self, top):
        return f"SELECT * FROM songs LIMIT {top}"


class Payload:
    def items(self):
        return []


class AuditLog:
    def info(self, message):
        return message

    def execute(self, query):
        return query
