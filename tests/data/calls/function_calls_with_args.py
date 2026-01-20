def bar(val):
    return val * 2


def foo(value):
    result = bar(value)
    print(result)
    return result

def baz():
    return foo(32)
