import { ShoppingCart } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCart } from '../context/CartContext';
import { useLocation } from 'wouter';

export default function CartButton() {
  const { getItemCount } = useCart();
  const [, setLocation] = useLocation();
  const itemCount = getItemCount();

  return (
    <div className="floating-cart">
      <Button
        className="relative bg-primary text-primary-foreground p-4 rounded-full shadow-lg hover:bg-primary/90"
        onClick={() => setLocation('/cart')}
        data-testid="button-floating-cart"
      >
        <ShoppingCart className="h-6 w-6" />
        <span
          className="absolute -top-2 -right-2 bg-destructive text-destructive-foreground text-xs rounded-full h-6 w-6 flex items-center justify-center"
          data-testid="text-cart-count"
        >
          {itemCount}
        </span>
      </Button>
    </div>
  );
}
