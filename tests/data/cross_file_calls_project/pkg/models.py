class Song:
    def get_related_songs_json(self, top):
        return f"SELECT * FROM songs LIMIT {top}"


class Payload:
    def items(self):
        return []
