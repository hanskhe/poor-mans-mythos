import { products } from "@/lib/catalog";

export default function Home() {
  return (
    <main>
      <h1>Shop</h1>
      <ul>
        {products.map((p) => (
          <li key={p.sku}>
            {p.name}: ${p.price}
          </li>
        ))}
      </ul>
    </main>
  );
}
