import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation } from 'wouter';
import { 
  Search, 
  MapPin, 
  Clock, 
  Star, 
  ShoppingBag,
  Percent,
  Filter,
  Grid,
  List,
  ChevronRight,
  Truck,
  Settings
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { Category, Restaurant, SpecialOffer } from '@shared/schema';

export default function HomePage() {
  const [, setLocation] = useLocation();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [clickCount, setClickCount] = useState(0);
  const [showAdminButtons, setShowAdminButtons] = useState(false);

  // نظام الـ 4 نقرات
  useEffect(() => {
    if (clickCount === 4) {
      setShowAdminButtons(true);
    }
    
    // إعادة تعيين العداد بعد 3 ثوانٍ
    const timer = setTimeout(() => {
      if (clickCount > 0 && clickCount < 4) {
        setClickCount(0);
      }
    }, 3000);

    return () => clearTimeout(timer);
  }, [clickCount]);

  const handleLogoClick = () => {
    setClickCount(prev => prev + 1);
  };

  // جلب البيانات
  const { data: categories } = useQuery<Category[]>({
    queryKey: ['/api/categories'],
  });

  const { data: restaurants } = useQuery<Restaurant[]>({
    queryKey: ['/api/restaurants', { categoryId: selectedCategory, search: searchQuery }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (selectedCategory !== 'all') params.append('categoryId', selectedCategory);
      if (searchQuery) params.append('search', searchQuery);
      
      const response = await fetch(`/api/restaurants?${params}`);
      return response.json();
    },
  });

  const { data: specialOffers } = useQuery<SpecialOffer[]>({
    queryKey: ['/api/special-offers'],
  });

  const filteredRestaurants = restaurants?.filter(restaurant => {
    const matchesSearch = !searchQuery || 
      restaurant.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      restaurant.description?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesCategory = selectedCategory === 'all' || restaurant.categoryId === selectedCategory;
    
    return matchesSearch && matchesCategory;
  }) || [];

  const handleRestaurantClick = (restaurantId: string) => {
    setLocation(`/restaurant/${restaurantId}`);
  };

  const parseDecimal = (value: string | null): number => {
    if (!value) return 0;
    const num = parseFloat(value);
    return isNaN(num) ? 0 : num;
  };

  return (
    <div className="min-h-screen bg-gray-50" dir="rtl">
      {/* Header */}
      <header className="bg-white shadow-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo مع نظام الـ 4 نقرات */}
            <div className="flex items-center gap-3 cursor-pointer" onClick={handleLogoClick}>
              <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg flex items-center justify-center">
                <ShoppingBag className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">السريع ون</h1>
                <p className="text-xs text-gray-500">توصيل سريع وآمن</p>
              </div>
              
              {/* مؤشر النقرات */}
              {clickCount > 0 && clickCount < 4 && (
                <div className="flex gap-1 mr-2">
                  {[...Array(4)].map((_, i) => (
                    <div
                      key={i}
                      className={`w-2 h-2 rounded-full ${
                        i < clickCount ? 'bg-orange-500' : 'bg-gray-300'
                      }`}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* أزرار الإدارة (تظهر بعد 4 نقرات) */}
            {showAdminButtons && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setLocation('/admin-login')}
                  className="flex items-center gap-2"
                >
                  <Settings className="h-4 w-4" />
                  لوحة التحكم
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setLocation('/driver-login')}
                  className="flex items-center gap-2"
                >
                  <Truck className="h-4 w-4" />
                  تطبيق السائق
                </Button>
              </div>
            )}

            {/* العنوان والموقع */}
            <div className="flex items-center gap-2 text-sm text-gray-600">
              <MapPin className="h-4 w-4" />
              <span>صنعاء، اليمن</span>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="bg-gradient-to-br from-orange-500 to-orange-600 text-white py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-4xl font-bold mb-4">اطلب طعامك المفضل</h2>
            <p className="text-xl mb-8 opacity-90">توصيل سريع من أفضل المطاعم في صنعاء</p>
            
            {/* شريط البحث */}
            <div className="max-w-2xl mx-auto relative">
              <Search className="absolute right-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <Input
                type="text"
                placeholder="ابحث عن مطعم أو وجبة..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pr-12 pl-4 py-4 text-lg rounded-xl border-0 shadow-lg"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* العروض الخاصة */}
        {specialOffers && specialOffers.length > 0 && (
          <section className="mb-12">
            <div className="flex items-center gap-2 mb-6">
              <Percent className="h-6 w-6 text-orange-500" />
              <h3 className="text-2xl font-bold text-gray-900">العروض الخاصة</h3>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {specialOffers.slice(0, 3).map((offer) => (
                <Card key={offer.id} className="overflow-hidden hover:shadow-lg transition-shadow cursor-pointer">
                  <div className="h-48 bg-gradient-to-br from-green-400 to-green-500 flex items-center justify-center">
                    {offer.image ? (
                      <img src={offer.image} alt={offer.title} className="w-full h-full object-cover" />
                    ) : (
                      <Percent className="h-16 w-16 text-white" />
                    )}
                  </div>
                  <CardContent className="p-4">
                    <h4 className="font-bold text-lg mb-2">{offer.title}</h4>
                    <p className="text-gray-600 text-sm mb-3">{offer.description}</p>
                    <div className="flex items-center justify-between">
                      {offer.discountPercent && (
                        <Badge className="bg-green-100 text-green-800">
                          خصم {offer.discountPercent}%
                        </Badge>
                      )}
                      {offer.discountAmount && (
                        <Badge className="bg-green-100 text-green-800">
                          خصم {parseDecimal(offer.discountAmount)} ريال
                        </Badge>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </section>
        )}

        {/* التصنيفات والمطاعم */}
        <section>
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-2xl font-bold text-gray-900">المطاعم</h3>
            <div className="flex items-center gap-4">
              {/* تبديل العرض */}
              <div className="flex items-center gap-1 bg-gray-100 rounded-lg p-1">
                <Button
                  variant={viewMode === 'grid' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('grid')}
                >
                  <Grid className="h-4 w-4" />
                </Button>
                <Button
                  variant={viewMode === 'list' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('list')}
                >
                  <List className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>

          {/* فلتر التصنيفات */}
          <div className="mb-8">
            <Tabs value={selectedCategory} onValueChange={setSelectedCategory}>
              <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 lg:grid-cols-6 h-auto">
                <TabsTrigger value="all" className="py-3">
                  جميع المطاعم
                </TabsTrigger>
                {categories?.map((category) => (
                  <TabsTrigger key={category.id} value={category.id} className="py-3">
                    {category.name}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>

          {/* قائمة المطاعم */}
          {filteredRestaurants.length > 0 ? (
            <div className={`grid gap-6 ${
              viewMode === 'grid' 
                ? 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3' 
                : 'grid-cols-1'
            }`}>
              {filteredRestaurants.map((restaurant) => (
                <Card 
                  key={restaurant.id} 
                  className="overflow-hidden hover:shadow-lg transition-all duration-200 cursor-pointer group"
                  onClick={() => handleRestaurantClick(restaurant.id)}
                >
                  <div className="h-48 bg-gradient-to-br from-gray-200 to-gray-300 flex items-center justify-center overflow-hidden">
                    {restaurant.image ? (
                      <img 
                        src={restaurant.image} 
                        alt={restaurant.name}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
                      />
                    ) : (
                      <ShoppingBag className="h-16 w-16 text-gray-400" />
                    )}
                  </div>
                  
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-bold text-lg group-hover:text-orange-600 transition-colors">
                        {restaurant.name}
                      </h4>
                      {restaurant.isOpen ? (
                        <Badge className="bg-green-100 text-green-800">مفتوح</Badge>
                      ) : (
                        <Badge variant="secondary">مغلق</Badge>
                      )}
                    </div>
                    
                    {restaurant.description && (
                      <p className="text-gray-600 text-sm mb-3 line-clamp-2">
                        {restaurant.description}
                      </p>
                    )}
                    
                    <div className="flex items-center justify-between text-sm text-gray-500">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-1">
                          <Star className="h-4 w-4 text-yellow-500" />
                          <span>{parseDecimal(restaurant.rating)}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="h-4 w-4" />
                          <span>{restaurant.deliveryTime}</span>
                        </div>
                      </div>
                      <div className="text-left">
                        <p className="text-xs">رسوم التوصيل</p>
                        <p className="font-medium text-gray-900">
                          {parseDecimal(restaurant.deliveryFee)} ريال
                        </p>
                      </div>
                    </div>
                    
                    <div className="mt-3 pt-3 border-t flex items-center justify-between">
                      <span className="text-xs text-gray-500">
                        أقل طلب: {parseDecimal(restaurant.minimumOrder)} ريال
                      </span>
                      <ChevronRight className="h-4 w-4 text-gray-400 group-hover:text-orange-600 transition-colors" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <ShoppingBag className="h-16 w-16 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">لا توجد مطاعم</h3>
              <p className="text-gray-500">
                {searchQuery 
                  ? `لم نجد مطاعم تطابق "${searchQuery}"`
                  : 'لا توجد مطاعم متاحة في الوقت الحالي'
                }
              </p>
            </div>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 bg-orange-500 rounded-lg flex items-center justify-center">
                  <ShoppingBag className="h-5 w-5 text-white" />
                </div>
                <h3 className="text-xl font-bold">السريع ون</h3>
              </div>
              <p className="text-gray-400">
                أفضل تطبيق توصيل طعام في اليمن. نوصل لك طعامك المفضل بسرعة وأمان.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">روابط سريعة</h4>
              <ul className="space-y-2 text-gray-400">
                <li><a href="#" className="hover:text-white transition-colors">من نحن</a></li>
                <li><a href="#" className="hover:text-white transition-colors">اتصل بنا</a></li>
                <li><a href="#" className="hover:text-white transition-colors">الشروط والأحكام</a></li>
                <li><a href="#" className="hover:text-white transition-colors">سياسة الخصوصية</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">تواصل معنا</h4>
              <div className="space-y-2 text-gray-400">
                <p>📞 +967 1 234 567</p>
                <p>📧 info@sareeone.com</p>
                <p>📍 صنعاء، اليمن</p>
              </div>
            </div>
          </div>
          
          <div className="border-t border-gray-800 mt-8 pt-8 text-center text-gray-400">
            <p>&copy; 2024 السريع ون. جميع الحقوق محفوظة.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}