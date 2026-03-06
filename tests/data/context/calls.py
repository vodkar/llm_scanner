def foo():
    return bar()

def bar():
    return "vulnerable"

def func1():
    foo()
    func2()
    
def func2():
    print("Hello, World!")
    
def main():
    func1()
    
if __name__ == "__main__":
    main()