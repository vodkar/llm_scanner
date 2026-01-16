a = 1
b = 'asdeasd'
c = b
d = a + 5
e = b + 'xyz'
f = d + a
g = b + str(d)
h = b + e

def my_function(param1, param2: str='default'):
    local_var = param1 + param2
    return local_var

my_function(b, 'test')
s = my_function(e)
digit = my_function(str(d), '123')

class MyClass:
    class_var = 10

    def __init__(self, instance_var: int):
        self.instance_var = instance_var

    def method(self, add_value):
        result = self.instance_var + add_value
        return result
    
obj1 = MyClass(5)
obj2 = MyClass(int(digit))