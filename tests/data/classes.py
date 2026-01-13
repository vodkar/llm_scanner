from dataclasses import dataclass


@dataclass(frozen=True)
class Product:
    sku: str
    name: str
    price: float


@dataclass
class OrderItem(
    object
):
    product: Product
    qty: int

    def subtotal(self) -> float:
        return round(self.qty * self.product.price, 2)
