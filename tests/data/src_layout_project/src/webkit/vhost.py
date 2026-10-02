from webkit import resource
from webkit.resource import safe_repr


def missing_host(host):
    return resource.ErrorPage().render(safe_repr(host))
