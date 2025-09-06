import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation } from 'wouter';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Gift, Truck, Clock, Star, Zap, Percent } from 'lucide-react';
import CategoryTabs from '../components/CategoryTabs';
import RestaurantCard from '../components/RestaurantCard';
import type { Restaurant } from '@shared/schema';

export default function Home() {
  const [, setLocation] = useLocation();
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const { data: restaurants, isLoading } = useQuery<Restaurant[]>({
    queryKey: ['/api/restaurants', ...(selectedCategory ? [`?categoryId=${selectedCategory}`] : [])],
  });

  const handleRestaurantClick = (restaurantId: string) => {
    setLocation(`/restaurant/${restaurantId}`);
  };

  return (
    <div>
      {/* Special Offers */}
      <section className="mb-6">
        <h3 className="text-lg font-bold text-foreground mb-4 px-4 flex items-center gap-2">
          <Zap className="h-5 w-5 text-primary" />
          العروض الخاصة
        </h3>
        <div className="px-4 space-y-3">
          <Card className="bg-gradient-to-r from-primary/20 to-primary/10 border-primary/30 overflow-hidden">
            <CardContent className="p-0">
              <div className="flex items-center">
                <div className="w-20 h-20 bg-primary/20 flex items-center justify-center">
                  <Gift className="h-10 w-10 text-primary" />
                </div>
                <div className="flex-1 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-foreground">خصم 30% على الطلب الأول</h4>
                      <p className="text-sm text-muted-foreground">استخدم كود: WELCOME30</p>
                    </div>
                    <Badge className="bg-primary">جديد</Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-r from-green-500/20 to-green-500/10 border-green-500/30 overflow-hidden">
            <CardContent className="p-0">
              <div className="flex items-center">
                <div className="w-20 h-20 bg-green-500/20 flex items-center justify-center">
                  <Truck className="h-10 w-10 text-green-500" />
                </div>
                <div className="flex-1 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-foreground">توصيل مجاني للطلبات فوق 50 ريال</h4>
                      <p className="text-sm text-muted-foreground">لفترة محدودة</p>
                    </div>
                    <Badge className="bg-green-500">مميز</Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-yellow-500/20 to-yellow-500/10 border-yellow-500/30 overflow-hidden">
            <CardContent className="p-0">
              <div className="flex items-center">
                <div className="w-20 h-20 bg-yellow-500/20 flex items-center justify-center">
                  <Clock className="h-10 w-10 text-yellow-500" />
                </div>
                <div className="flex-1 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-foreground">طلب سريع في 15 دقيقة</h4>
                      <p className="text-sm text-muted-foreground">للطلبات داخل المدينة</p>
                    </div>
                    <Badge className="bg-yellow-500">سريع</Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-r from-purple-500/20 to-purple-500/10 border-purple-500/30 overflow-hidden">
            <CardContent className="p-0">
              <div className="flex items-center">
                <div className="w-20 h-20 bg-purple-500/20 flex items-center justify-center">
                  <Star className="h-10 w-10 text-purple-500" />
                </div>
                <div className="flex-1 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-bold text-foreground">نقاط مكافآت مضاعفة</h4>
                      <p className="text-sm text-muted-foreground">اجمع نقاط واحصل على خصومات</p>
                    </div>
                    <Badge className="bg-purple-500">VIP</Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Category Tabs */}
      <CategoryTabs 
        selectedCategory={selectedCategory}
        onCategoryChange={setSelectedCategory}
      />

      {/* Restaurant List */}
      <section className="px-4 space-y-4">
        <h3 className="text-lg font-bold text-foreground mb-4">المطاعم القريبة منك</h3>
        
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-card rounded-xl border border-border overflow-hidden">
                <div className="w-full h-48 bg-muted animate-pulse" />
                <div className="p-4 space-y-3">
                  <div className="h-4 bg-muted rounded animate-pulse" />
                  <div className="h-3 bg-muted rounded w-3/4 animate-pulse" />
                  <div className="h-3 bg-muted rounded w-1/2 animate-pulse" />
                </div>
              </div>
            ))}
          </div>
        ) : restaurants?.length ? (
          restaurants.map((restaurant) => (
            <RestaurantCard
              key={restaurant.id}
              restaurant={restaurant}
              onClick={() => handleRestaurantClick(restaurant.id)}
            />
          ))
        ) : (
          <div className="text-center text-muted-foreground py-8">
            <p>لا توجد مطاعم متاحة في هذا التصنيف</p>
          </div>
        )}
      </section>
    </div>
  );
}
