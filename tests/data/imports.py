from .function import sample_function_body
from .classes import Product, OrderItem
from dataclasses import dataclass
from unknown_module import unknown_function

sample_function_body(5, 7)
product = Product(sku="12345", name="Widget", price=19.99)
order_item = OrderItem(product=product, qty=3)
print(order_item.subtotal())
