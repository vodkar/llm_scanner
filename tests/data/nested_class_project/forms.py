from base import Base


class Outer:
    class Meta:
        def nested_only(self):
            return 1


class Meta(Base):
    def render(self):
        return self.run()
