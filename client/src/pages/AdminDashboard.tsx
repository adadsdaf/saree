import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { 
  BarChart3, 
  Users, 
  ShoppingBag, 
  DollarSign, 
  Settings, 
  LogOut,
  Package,
  Truck,
  Store,
  Eye,
  Edit,
  Trash2
} from 'lucide-react';

interface AdminDashboardProps {
  onLogout: () => void;
}

export const AdminDashboard: React.FC<AdminDashboardProps> = ({ onLogout }) => {
  const { logout } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');

  const handleLogout = () => {
    logout();
    onLogout();
  };

  const stats = [
    { title: 'إجمالي الطلبات', value: '2,345', icon: ShoppingBag, color: 'text-blue-600' },
    { title: 'العملاء النشطين', value: '1,234', icon: Users, color: 'text-green-600' },
    { title: 'إجمالي المبيعات', value: '₪45,678', icon: DollarSign, color: 'text-orange-600' },
    { title: 'السائقين المتاحين', value: '23', icon: Truck, color: 'text-purple-600' },
  ];

  return (
    <div className="min-h-screen bg-gray-50" dir="rtl">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <Settings className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">لوحة التحكم</h1>
                <p className="text-sm text-gray-500">إدارة نظام التوصيل</p>
              </div>
            </div>
            <Button 
              variant="outline" 
              onClick={handleLogout}
              className="flex items-center gap-2"
            >
              <LogOut className="h-4 w-4" />
              تسجيل الخروج
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Notification System */}
        <div className="mb-8">
          <NotificationSystem userType="admin" />
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <Card key={index}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">{stat.title}</p>
                      <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                    </div>
                    <Icon className={`h-8 w-8 ${stat.color}`} />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Tabs Navigation */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
            <TabsTrigger value="orders">الطلبات</TabsTrigger>
            <TabsTrigger value="restaurants">المطاعم</TabsTrigger>
            <TabsTrigger value="drivers">السائقين</TabsTrigger>
            <TabsTrigger value="categories">الفئات</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5" />
                    الطلبات الحديثة
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {[1, 2, 3].map((order) => (
                      <div key={order} className="flex items-center justify-between p-3 border rounded-lg">
                        <div>
                          <p className="font-medium">طلب #{1000 + order}</p>
                          <p className="text-sm text-gray-600">مطعم الوزيكو للعربكة</p>
                        </div>
                        <Badge variant="secondary">قيد التحضير</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5" />
                    السائقين النشطين
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {['أحمد محمد', 'علي حسن', 'سارة أحمد'].map((driver, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div>
                          <p className="font-medium">{driver}</p>
                          <p className="text-sm text-gray-600">متاح للتوصيل</p>
                        </div>
                        <Badge variant="default" className="bg-green-100 text-green-800">
                          نشط
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="orders" className="space-y-6">
            <AdminOrders />
          </TabsContent>

          <TabsContent value="restaurants" className="space-y-6">
            <AdminRestaurants />
          </TabsContent>

          <TabsContent value="drivers" className="space-y-6">
            <AdminDrivers />
          </TabsContent>

          <TabsContent value="categories" className="space-y-6">
            <AdminCategories />
          </TabsContent>

          <TabsContent value="menu" className="space-y-6">
            <AdminMenuItems />
          </TabsContent>

          <TabsContent value="offers" className="space-y-6">
            <AdminOffers />
          </TabsContent>

          <TabsContent value="menu" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>إدارة قوائم الطعام</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {['عربكة بالقشطة والعسل', 'معصوب بالقشطة والعسل', 'مياه معدنية', 'كومبو عربكة خاص'].map((item, index) => (
                    <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center gap-4">
                        <Menu className="h-8 w-8 text-gray-400" />
                        <div>
                          <p className="font-medium">{item}</p>
                          <p className="text-sm text-gray-600">{25 + index * 15} ريال</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="default" className="bg-green-100 text-green-800">
                          متوفر
                        </Badge>
                        <Button variant="outline" size="sm">
                          <Edit className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="offers" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>إدارة العروض الخاصة</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {['خصم 30% على الطلب الأول', 'توصيل مجاني فوق 50 ريال', 'عرض رمضان الخاص'].map((offer, index) => (
                    <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center gap-4">
                        <Percent className="h-8 w-8 text-gray-400" />
                        <div>
                          <p className="font-medium">{offer}</p>
                          <p className="text-sm text-gray-600">صالح لمدة {7 + index * 3} أيام</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="default" className="bg-orange-100 text-orange-800">
                          نشط
                        </Badge>
                        <Button variant="outline" size="sm">
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="outline" size="sm">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};