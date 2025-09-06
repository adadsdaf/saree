import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MapPin, Package, Phone, Check, X, Navigation, DollarSign, Clock, User, Star } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';
import type { Order, Driver } from '@shared/schema';

export default function Delivery() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  // Mock driver data - in real app this would come from authentication
  const [currentDriver] = useState<Driver>({
    id: '1',
    name: 'أحمد محمد',
    phone: '+967771234567',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    isAvailable: true,
    isActive: true,
    currentLocation: 'صنعاء، شارع الزبيري',
    earnings: '2500',
    createdAt: new Date(),
  });

  const [driverStatus, setDriverStatus] = useState(currentDriver.isAvailable);

  const { data: availableOrders, isLoading } = useQuery<Order[]>({
    queryKey: ['/api/orders', { status: 'confirmed' }],
  });

  const { data: activeOrders } = useQuery<Order[]>({
    queryKey: ['/api/orders', { driverId: currentDriver.id, status: 'on_way' }],
  });

  const acceptOrderMutation = useMutation({
    mutationFn: async (orderId: string) => {
      const response = await apiRequest('PUT', `/api/orders/${orderId}`, {
        status: 'on_way',
        driverId: currentDriver.id,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/orders'] });
      toast({
        title: "تم قبول الطلب",
        description: "يمكنك الآن بدء رحلة التوصيل",
      });
    },
  });

  const completeOrderMutation = useMutation({
    mutationFn: async (orderId: string) => {
      const response = await apiRequest('PUT', `/api/orders/${orderId}`, {
        status: 'delivered',
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/orders'] });
      toast({
        title: "تم تسليم الطلب",
        description: "تم تحديث حالة الطلب بنجاح",
      });
    },
  });

  const updateDriverStatus = useMutation({
    mutationFn: async (isAvailable: boolean) => {
      const response = await apiRequest('PUT', `/api/drivers/${currentDriver.id}`, {
        isAvailable,
      });
      return response.json();
    },
    onSuccess: (_, isAvailable: boolean) => {
      setDriverStatus(isAvailable);
      toast({
        title: isAvailable ? "أنت متاح الآن" : "أنت غير متاح",
        description: isAvailable ? "ستتلقى طلبات جديدة" : "لن تتلقى طلبات جديدة",
      });
    },
  });

  const getOrderItems = (itemsString: string) => {
    try {
      return JSON.parse(itemsString);
    } catch {
      return [];
    }
  };

  // دالة لتحويل القيم الرقمية من string إلى number
  const parseDecimal = (value: string | null): number => {
    if (!value) return 0;
    const num = parseFloat(value);
    return isNaN(num) ? 0 : num;
  };

  const todayEarnings = 450; // Mock data
  const todayOrders = 8; // Mock data

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border p-4 sticky top-0 z-40">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-primary rounded-full flex items-center justify-center">
              <User className="h-6 w-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-foreground">{currentDriver.name}</h1>
              <p className="text-sm text-muted-foreground">سائق توصيل</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="driver-status" className="text-sm text-foreground">متاح</Label>
            <Switch
              id="driver-status"
              checked={driverStatus}
              onCheckedChange={(checked) => updateDriverStatus.mutate(checked)}
              data-testid="switch-driver-status"
            />
          </div>
        </div>
      </header>

      <div className="p-4 space-y-6">
        {/* Today's Stats */}
        <div className="grid grid-cols-2 gap-4">
          <Card>
            <CardContent className="p-4 text-center">
              <DollarSign className="h-8 w-8 text-green-500 mx-auto mb-2" />
              <h3 className="text-lg font-bold text-foreground" data-testid="today-earnings">
                {todayEarnings} ريال
              </h3>
              <p className="text-sm text-muted-foreground">أرباح اليوم</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-4 text-center">
              <Package className="h-8 w-8 text-primary mx-auto mb-2" />
              <h3 className="text-lg font-bold text-foreground" data-testid="today-orders">
                {todayOrders}
              </h3>
              <p className="text-sm text-muted-foreground">طلبات اليوم</p>
            </CardContent>
          </Card>
        </div>

        {/* Active Orders */}
        {activeOrders && activeOrders.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Package className="h-5 w-5 text-primary" />
                الطلبات الحالية
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {activeOrders.map((order) => (
                <div key={order.id} className="border border-border rounded-lg p-4">
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h4 className="font-bold text-foreground">طلب #{order.id}</h4>
                      <p className="text-sm text-muted-foreground">{order.customerName}</p>
                    </div>
                    <Badge className="bg-orange-500 hover:bg-orange-500">جاري التوصيل</Badge>
                  </div>
                  
                  <div className="space-y-2 mb-4">
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-foreground">{order.deliveryAddress}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Phone className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-foreground">{order.customerPhone}</span>
                    </div>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button 
                      className="flex-1 gap-2"
                      onClick={() => window.open(`tel:${order.customerPhone}`)}
                      data-testid={`button-call-${order.id}`}
                    >
                      <Phone className="h-4 w-4" />
                      اتصال
                    </Button>
                    <Button 
                      className="flex-1 gap-2"
                      onClick={() => window.open(`https://maps.google.com/?q=${encodeURIComponent(order.deliveryAddress)}`)}
                      data-testid={`button-navigate-${order.id}`}
                    >
                      <Navigation className="h-4 w-4" />
                      التنقل
                    </Button>
                    <Button 
                      variant="outline"
                      className="flex-1 gap-2"
                      onClick={() => completeOrderMutation.mutate(order.id)}
                      disabled={completeOrderMutation.isPending}
                      data-testid={`button-complete-${order.id}`}
                    >
                      <Check className="h-4 w-4" />
                      تم التسليم
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Available Orders */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-primary" />
              الطلبات المتاحة
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!driverStatus ? (
              <div className="text-center py-8">
                <Clock className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">قم بتفعيل حالة التوفر لاستقبال الطلبات</p>
              </div>
            ) : isLoading ? (
              <div className="space-y-4">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="border border-border rounded-lg p-4 animate-pulse">
                    <div className="h-4 bg-muted rounded w-3/4 mb-2" />
                    <div className="h-3 bg-muted rounded w-1/2 mb-3" />
                    <div className="h-3 bg-muted rounded w-2/3" />
                  </div>
                ))}
              </div>
            ) : availableOrders && availableOrders.length > 0 ? (
              <div className="space-y-4">
                {availableOrders.map((order) => {
                  const items = getOrderItems(order.items);
                  const totalAmount = parseDecimal(order.totalAmount);
                  const commission = Math.round(totalAmount * 0.1);
                  
                  return (
                    <div key={order.id} className="border border-border rounded-lg p-4">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <h4 className="font-bold text-foreground">طلب #{order.id}</h4>
                          <p className="text-sm text-muted-foreground">{order.customerName}</p>
                        </div>
                        <div className="text-right">
                          <p className="font-bold text-primary">{totalAmount} ريال</p>
                          <p className="text-sm text-muted-foreground">العمولة: {commission} ريال</p>
                        </div>
                      </div>
                      
                      <div className="space-y-2 mb-4">
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm text-foreground">{order.deliveryAddress}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Package className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm text-foreground">
                            {items.length} عنصر - {order.paymentMethod === 'cash' ? 'دفع نقدي' : 'مدفوع مسبقاً'}
                          </span>
                        </div>
                      </div>
                      
                      <div className="flex gap-2">
                        <Button 
                          className="flex-1"
                          onClick={() => acceptOrderMutation.mutate(order.id)}
                          disabled={acceptOrderMutation.isPending}
                          data-testid={`button-accept-${order.id}`}
                        >
                          قبول الطلب
                        </Button>
                        <Button 
                          variant="outline"
                          onClick={() => window.open(`https://maps.google.com/?q=${encodeURIComponent(order.deliveryAddress)}`)}
                          data-testid={`button-view-location-${order.id}`}
                        >
                          عرض الموقع
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8">
                <Package className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">لا توجد طلبات متاحة في الوقت الحالي</p>
                <p className="text-sm text-muted-foreground mt-2">سيتم إشعارك عند توفر طلبات جديدة</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Earnings Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Star className="h-5 w-5 text-primary" />
              ملخص الأرباح
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-center">
              <div>
                <p className="text-sm text-muted-foreground">هذا الأسبوع</p>
                <p className="text-lg font-bold text-foreground">1,250 ريال</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">هذا الشهر</p>
                <p className="text-lg font-bold text-foreground">4,800 ريال</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">متوسط الطلب</p>
                <p className="text-lg font-bold text-foreground">85 ريال</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">التقييم</p>
                <p className="text-lg font-bold text-foreground">4.9 ⭐</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}