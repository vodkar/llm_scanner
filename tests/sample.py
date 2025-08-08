import csv
import json
import re
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

_log_lock = threading.Lock()
def log(msg: str):
    with _log_lock:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {msg}")

def retry(times: int = 3, delay: float = 0.1, exceptions: tuple = (Exception,)):
    def deco(fn: Callable):
        def wrapped(*a, **kw):
            last = None
            for i in range(1, times + 1):
                try: return fn(*a, **kw)
                except exceptions as e:
                    last = e; log(f"{fn.__name__} failed ({i}/{times}): {e}"); time.sleep(delay)
            raise last
        return wrapped
    return deco

# ---------- domain ----------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@dataclass(frozen=True)
class Customer:
    email: str
    name: str
    id: str = field(default_factory=lambda: f"cus_{uuid.uuid4().hex[:8]}")
    def __post_init__(self):
        if not EMAIL_RE.match(self.email):
            raise ValueError(f"Invalid email: {self.email}")

@dataclass(frozen=True)
class Product: sku: str; name: str; price: float

class InventoryError(Exception): ...

class Inventory:
    def __init__(self):
        self._stock: Dict[str, int] = {}; self._lock = threading.Lock()
    def add(self, sku: str, qty: int):
        if qty < 0: raise ValueError("qty >= 0")
        with self._lock:
            self._stock[sku] = self._stock.get(sku, 0) + qty; log(f"Stock[{sku}]={self._stock[sku]}")
    def available(self, sku: str) -> int:
        with self._lock: return self._stock.get(sku, 0)
    def take(self, sku: str, qty: int):
        with self._lock:
            have = self._stock.get(sku, 0)
            if qty <= 0: raise ValueError("qty > 0")
            if have < qty: raise InventoryError(f"Need {qty}, have {have} of {sku}")
            self._stock[sku] = have - qty; log(f"Took {qty} {sku}. Left {self._stock[sku]}")
    def low_stock(self, threshold: int = 2) -> List[Tuple[str, int]]:
        with self._lock:
            lows = [(sku, qty) for sku, qty in self._stock.items() if qty <= threshold]
        return sorted(lows, key=lambda x: x[1])

@dataclass
class OrderItem:
    product: Product; qty: int
    def subtotal(self) -> float: return round(self.qty * self.product.price, 2)

class Coupon(ABC):
    @abstractmethod
    def apply(self, total: float) -> float: ...

@dataclass
class PercentCoupon(Coupon):
    percent: float; code: str = field(default="WELCOME10")
    def apply(self, total: float) -> float:
        cut = round(total * (self.percent / 100), 2); log(f"Coupon {self.code}: -{cut:.2f}")
        return max(0.0, round(total - cut, 2))

@dataclass
class FixedCoupon(Coupon):
    amount: float; code: str = field(default="SAVE5")
    def apply(self, total: float) -> float:
        log(f"Coupon {self.code}: -{self.amount:.2f}")
        return max(0.0, round(total - self.amount, 2))

class PaymentError(Exception): ...

class PaymentProcessor(ABC):
    @abstractmethod
    def charge(self, amount: float, reference: str) -> str: ...

class MockProcessor(PaymentProcessor):
    def charge(self, amount: float, reference: str) -> str:
        cents = int(round((amount - int(amount)) * 100))
        if cents == 13: raise PaymentError("Gateway refused 13 cents")
        tx = f"tx_{uuid.uuid4().hex[:8]}"; log(f"Charged {amount:.2f} for {reference} -> {tx}"); return tx

@dataclass
class Order:
    customer: Customer
    items: List[OrderItem] = field(default_factory=list)
    coupon: Optional[Coupon] = None
    id: str = field(default_factory=lambda: f"ord_{uuid.uuid4().hex[:8]}")
    paid_tx: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def add_item(self, product: Product, qty: int, inventory: Inventory):
        inventory.take(product.sku, qty); self.items.append(OrderItem(product, qty)); log(f"Order {self.id} + {product.sku} x{qty}")
    def set_coupon(self, coupon: Coupon): self.coupon = coupon; log(f"Order {self.id} coupon={coupon}")
    def total_before_discounts(self) -> float: return round(sum(i.subtotal() for i in self.items), 2)
    def total(self) -> float:
        total = self.total_before_discounts()
        if self.coupon: total = self.coupon.apply(total)
        return round(total, 2)
    @retry(times=3, delay=0.05, exceptions=(PaymentError,))
    def pay(self, processor: PaymentProcessor) -> str:
        if self.paid_tx: raise ValueError("Already paid")
        if not self.items: raise ValueError("Empty order")
        tx = processor.charge(self.total(), self.id); self.paid_tx = tx; log(f"Order {self.id} paid -> {tx}"); return tx
    def to_json(self) -> str:
        data = {"id": self.id, "customer": asdict(self.customer), "created_at": self.created_at,
                "items": [{"sku": it.product.sku, "name": it.product.name, "price": it.product.price, "qty": it.qty} for it in self.items],
                "coupon": asdict(self.coupon) if self.coupon else None, "paid_tx": self.paid_tx}
        return json.dumps(data, indent=2)
    @staticmethod
    def from_json(s: str) -> "Order":
        raw = json.loads(s); order = Order(customer=Customer(**raw["customer"]), id=raw["id"], created_at=raw.get("created_at", time.time()))
        for it in raw["items"]:
            product = Product(it["sku"], it["name"], it["price"]); order.items.append(OrderItem(product, it["qty"]))
        c = raw.get("coupon"); 
        if c: order.coupon = PercentCoupon(**c) if "percent" in c else FixedCoupon(**c)
        order.paid_tx = raw.get("paid_tx"); return order

class OrderRepository:
    def __init__(self, folder: Path):
        self.folder = Path(folder); self.folder.mkdir(parents=True, exist_ok=True)
    def _path(self, order_id: str) -> Path: return self.folder / f"{order_id}.json"
    def save(self, order: Order):
        path = self._path(order.id); tmp = path.with_suffix(".json.tmp")
        tmp.write_text(order.to_json(), encoding="utf-8"); tmp.replace(path); log(f"Saved {order.id} -> {path}")
    def load(self, order_id: str) -> Order:
        return Order.from_json(self._path(order_id).read_text(encoding="utf-8"))
    def all_orders(self) -> Iterable[Order]:
        for p in sorted(self.folder.glob("*.json")): yield Order.from_json(p.read_text(encoding="utf-8"))

def iter_order_lines(repo: OrderRepository) -> Iterable[Tuple[str, str, str, int, float]]:
    for o in repo.all_orders():
        for it in o.items:
            yield (o.id, o.customer.email, it.product.sku, it.qty, it.subtotal())

def summarize_orders(repo: OrderRepository) -> Dict[str, float]:
    totals: Dict[str, float] = {}
    for _, _, sku, _, sub in iter_order_lines(repo):
        totals[sku] = round(totals.get(sku, 0.0) + sub, 2)
    return dict(sorted(totals.items(), key=lambda kv: kv[0]))

def export_orders_csv(repo: OrderRepository, path: Path):
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["order_id", "email", "sku", "qty", "subtotal"])
        for row in iter_order_lines(repo): w.writerow(row)
    log(f"Exported CSV -> {path}")

class Receipt:
    def __init__(self, order: Order): self.order = order
    def __str__(self) -> str:
        lines = [f"Receipt for {self.order.customer.name} <{self.order.customer.email}>",
                 f"Order {self.order.id} on {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.order.created_at))}",
                 "-"*50]
        for it in self.order.items:
            lines.append(f"{it.product.name:20} x{it.qty:<3} @ {it.product.price:>5.2f} = {it.subtotal():>6.2f}")
        lines.append("-"*50)
        if self.order.coupon: lines.append(f"Discount via {self.order.coupon}:")
        lines.append(f"TOTAL: {self.order.total():.2f}")
        if self.order.paid_tx: lines.append(f"PAID: {self.order.paid_tx}")
        return "\n".join(lines)

def demo():
    inventory = Inventory()
    p1 = Product("SKU-APPLE", "Apple", 0.99); p2 = Product("SKU-BREAD", "Bread", 2.49); p3 = Product("SKU-COFFEE", "Coffee Beans", 7.13)
    for sku, qty in [(p1.sku, 10), (p2.sku, 5), (p3.sku, 2)]: inventory.add(sku, qty)

    customer = Customer(email="alice@example.com", name="Alice")
    order = Order(customer=customer)
    order.add_item(p1, 4, inventory); order.add_item(p2, 2, inventory); order.add_item(p3, 1, inventory)
    order.set_coupon(PercentCoupon(percent=10, code="WELCOME10"))

    proc = MockProcessor()
    try: order.pay(proc)
    except PaymentError as e: log(f"Payment failed permanently: {e}")

    print(Receipt(order))

    repo = OrderRepository(Path("orders")); repo.save(order)
    loaded = repo.load(order.id); assert loaded.total() == order.total(); log(f"Loaded {loaded.id} total={loaded.total():.2f}")
    export_orders_csv(repo, Path("orders.csv"))
    for sku, qty in inventory.low_stock(3): log(f"LOW STOCK {sku}: {qty}")

if __name__ == "__main__": demo()
    loaded = repo.load(order.id); assert loaded.total() == order.total(); log(f"Loaded {loaded.id} total={loaded.total():.2f}")
    export_orders_csv(repo, Path("orders.csv"))
    for sku, qty in inventory.low_stock(3): log(f"LOW STOCK {sku}: {qty}")

if __name__ == "__main__": demo()
    loaded = repo.load(order.id); assert loaded.total() == order.total(); log(f"Loaded {loaded.id} total={loaded.total():.2f}")
    export_orders_csv(repo, Path("orders.csv"))
    for sku, qty in inventory.low_stock(3): log(f"LOW STOCK {sku}: {qty}")

if __name__ == "__main__": demo()
