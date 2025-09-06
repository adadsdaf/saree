import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { NotificationSystem } from '@/components/NotificationSystem';
import { apiRequest } from '@/lib/queryClient';
import { 
  Truck, 
  MapPin, 
  Clock, 
  DollarSign, 
  LogOut,
  Navigation,
  Phone,
  CheckCircle,
  XCircle,
  Package,
  TrendingUp,
  Star
} from 'lucide-react';

export default function DriverDashboard() {
  const { user, logout } = useAuth();
  const [isAvailable, setIsAvailable] = useState(true);
  const [currentOrder, setCurrentOrder] = useState<any>(null);

  const { data: dashboardData, isLoading } = useQuery({
    queryKey: ['/api/driver/dashboard'],
    queryFn: async () => {
      const response = await apiRequest('GET', '/api/driver/dashboard', null, user?.token);
      return response.json();
    },
    refetchInterval: 10000, // تحديث كل 10 ثواني
  });

  const handleLogout = () => {
    logout();
  };

  const toggleAvailability = () => {
    setIsAvailable(!isAvailable);
  };

  const acceptOrder = (orderId: string) => {
    // TODO: إرسال طلب قبول الطلب إلى الخادم
    console.log('قبول الطلب:', orderId);
  };

  const completeOrder = () => {
    // TODO: إرسال طلب إكمال الطلب إلى الخادم
    setCurrentOrder(null);
  };

  const stats = dashboardData?.stats || {};
  const availableOrders = dashboardData?.availableOrders || [];
  const currentOrders = dashboardData?.currentOrders || [];

  const todayStats = [
    { title: 'توصيلات اليوم', value: stats.todayOrders || 0, icon: Package, color: 'text-blue-600' },
    { title: 'أرباح اليوم', value: `${stats.todayEarnings || 0} ريال`, icon: DollarSign, color: 'text-green-600' },
    { title: 'إجمالي الطلبات', value: stats.totalOrders || 0, icon: TrendingUp, color: 'text-orange-600' },
    { title: 'التقييم', value: stats.averageRating || '0.0', icon: Star, color: 'text-yellow-600' },
  ];

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-600">جاري تحميل البيانات...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50" dir="rtl">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-green-600 rounded-lg flex items-center justify-center">
                <Truck className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">تطبيق السائق</h1>
                <p className="text-sm text-gray-500">مرحباً {user?.name}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button 
                variant={isAvailable ? "default" : "secondary"}
                onClick={toggleAvailability}
                className={isAvailable ? "bg-green-600 hover:bg-green-700" : "bg-gray-500 hover:bg-gray-600"}
              >
                {isAvailable ? 'متاح' : 'غير متاح'}
              </Button>
              <Button 
                variant="outline" 
                onClick={handleLogout}
                className="flex items-center gap-2 hover:bg-red-50 hover:text-red-600 hover:border-red-200"
              >
                <LogOut className="h-4 w-4" />
                تسجيل الخروج
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Notification System */}
        <div className="mb-6">
          <NotificationSystem userType="driver" />
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {todayStats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <Card key={index} className="hover:shadow-lg transition-shadow duration-200">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600 mb-1">{stat.title}</p>
                      <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                    </div>
                    <Icon className={`h-8 w-8 ${stat.color}`} />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Current Order */}
        {currentOrders.length > 0 && (
          <Card className="mb-6 border-green-200 bg-green-50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-green-800">
                <Package className="h-5 w-5" />
                الطلب الحالي - #{currentOrders[0].orderNumber}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="font-medium">{currentOrders[0].customerName}</p>
                    <div className="flex items-center gap-2 text-sm text-gray-600 mt-1">
                      <Phone className="h-4 w-4" />
                      {currentOrders[0].customerPhone}
                    </div>
                    <div className="flex items-center gap-2 text-sm text-gray-600 mt-1">
                      <MapPin className="h-4 w-4" />
                      {JSON.parse(currentOrders[0].deliveryAddress).address}
                    </div>
                  </div>
                  <div>
                    <p className="font-medium">{currentOrders[0].restaurantId?.name || 'مطعم'}</p>
                    <p className="text-sm text-gray-600 mt-1">
                      {JSON.parse(currentOrders[0].items).length} عنصر
                    </p>
                    <p className="text-lg font-bold text-green-600 mt-2">{currentOrders[0].total} ريال</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <Button className="flex-1 bg-blue-600 hover:bg-blue-700">
                    <Navigation className="h-4 w-4 mr-2" />
                    فتح الخريطة
                  </Button>
                  <Button className="flex-1" onClick={completeOrder}>
                    <CheckCircle className="h-4 w-4 mr-2" />
                    تم التسليم
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Available Orders */}
        {isAvailable && currentOrders.length === 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                الطلبات المتاحة
              </CardTitle>
            </CardHeader>
            <CardContent>
              {availableOrders.length > 0 ? (
                <div className="space-y-4">
                  {availableOrders.map((order: any) => (
                    <div key={order.id} className="border rounded-lg p-4 hover:bg-gray-50 transition-colors">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <p className="font-medium">طلب #{order.orderNumber}</p>
                          <p className="text-sm text-gray-600">{order.customerName}</p>
                        </div>
                        <Badge variant="secondary">
                          {new Date(order.createdAt).toLocaleTimeString('ar-YE')}
                        </Badge>
                      </div>
                      
                      <div className="space-y-2 mb-4">
                        <div className="flex items-center gap-2 text-sm">
                          <Package className="h-4 w-4 text-gray-400" />
                          {order.restaurantId?.name || 'مطعم'}
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <MapPin className="h-4 w-4 text-gray-400" />
                          {JSON.parse(order.deliveryAddress).address}
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>المجموع: {order.total} ريال</span>
                          <span className="font-medium text-green-600">
                            رسوم التوصيل: {order.deliveryFee} ريال
                          </span>
                        </div>
                      </div>
                      
                      <div className="flex gap-3">
                        <Button 
                          className="flex-1 bg-green-600 hover:bg-green-700"
                          onClick={() => acceptOrder(order.id)}
                        >
                          <CheckCircle className="h-4 w-4 mr-2" />
                          قبول الطلب
                        </Button>
                        <Button variant="outline" className="flex-1 text-red-600 hover:bg-red-50">
                          <XCircle className="h-4 w-4 mr-2" />
                          رفض
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Clock className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">لا توجد طلبات متاحة حالياً</p>
                  <p className="text-sm text-gray-400 mt-2">سيتم إشعارك عند توفر طلبات جديدة</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Offline Status */}
        {!isAvailable && (
          <Card>
            <CardContent className="py-8">
              <div className="text-center">
                <Truck className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                <p className="text-lg font-medium text-gray-600 mb-2">أنت غير متاح حالياً</p>
                <p className="text-sm text-gray-400 mb-4">قم بتفعيل حالة المتاح لاستلام الطلبات</p>
                <Button onClick={toggleAvailability} className="bg-green-600 hover:bg-green-700">
                  تفعيل حالة المتاح
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}