from dataclasses import dataclass

def main() -> None:
    a = A(10, "hello")
    a.print()

@dataclass
class A:
    x: int
    y: str
    
    def print(self) -> None:
        print(f"A: x={self.x}, y={self.y}")
        