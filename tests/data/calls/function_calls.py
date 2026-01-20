def bar():
    return 1


def foo(value):
    result = bar()
    return bar()


def baz():
    return foo(bar())
