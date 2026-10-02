class ErrorPage:
    template = "<p>%(detail)s</p>"

    def render(self, detail):
        return self.template % {"detail": detail}


def safe_repr(value):
    return repr(value)
