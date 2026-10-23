export const products = [
  { sku: "mug", name: "Enamel mug", price: 18 },
  { sku: "tote", name: "Canvas tote", price: 24 },
  { sku: "cap", name: "Wool cap", price: 32 },
];

export const priceOf = (sku: string) => products.find((p) => p.sku === sku)?.price ?? 0;
