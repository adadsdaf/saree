import React from 'react';
import { Router, Route, Switch } from 'wouter';
import { CartProvider } from '@/context/CartContext';
import { AuthProvider } from '@/context/AuthContext';

// صفحات العميل
import HomePage from '@/pages/HomePage';
import RestaurantPage from '@/pages/RestaurantPage';
import CartPage from '@/pages/CartPage';
import OrderTrackingPage from '@/pages/OrderTrackingPage';
import ProfilePage from '@/pages/ProfilePage';

// صفحات الإدارة
import AdminLoginPage from '@/pages/admin/AdminLoginPage';
import AdminDashboard from '@/pages/admin/AdminDashboard';
import AdminRestaurants from '@/pages/admin/AdminRestaurants';
import AdminMenuItems from '@/pages/AdminMenuItems';
import AdminOffers from '@/pages/AdminOffers';

// صفحات السائق
import DriverLoginPage from '@/pages/driver/DriverLoginPage';
import DriverDashboard from '@/pages/DriverDashboard';

// مكونات مشتركة
import { AdminLayout } from '@/components/admin/AdminLayout';
import { ProtectedRoute } from '@/components/ProtectedRoute';

function App() {
  return (
    <AuthProvider>
      <CartProvider>
        <Router>
          <Switch>
            {/* مسارات العميل */}
            <Route path="/" component={HomePage} />
            <Route path="/restaurant/:id" component={RestaurantPage} />
            <Route path="/cart" component={CartPage} />
            <Route path="/order/:id" component={OrderTrackingPage} />
            <Route path="/profile" component={ProfilePage} />

            {/* مسارات الإدارة */}
            <Route path="/admin-login" component={AdminLoginPage} />
            
            <Route path="/admin">
              <ProtectedRoute userType="admin">
                <AdminLayout>
                  <AdminDashboard />
                </AdminLayout>
              </ProtectedRoute>
            </Route>
            
            <Route path="/admin/restaurants">
              <ProtectedRoute userType="admin">
                <AdminLayout>
                  <AdminRestaurants />
                </AdminLayout>
              </ProtectedRoute>
            </Route>
            
            <Route path="/admin/menu-items">
              <ProtectedRoute userType="admin">
                <AdminLayout>
                  <AdminMenuItems />
                </AdminLayout>
              </ProtectedRoute>
            </Route>
            
            <Route path="/admin/offers">
              <ProtectedRoute userType="admin">
                <AdminLayout>
                  <AdminOffers />
                </AdminLayout>
              </ProtectedRoute>
            </Route>

            {/* مسارات السائق */}
            <Route path="/driver-login" component={DriverLoginPage} />
            <Route path="/delivery">
              <ProtectedRoute userType="driver">
                <DriverDashboard />
              </ProtectedRoute>
            </Route>

            {/* صفحة 404 */}
            <Route>
              <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                  <h1 className="text-4xl font-bold text-gray-900 mb-4">404</h1>
                  <p className="text-gray-600 mb-8">الصفحة غير موجودة</p>
                  <a href="/" className="bg-orange-500 text-white px-6 py-3 rounded-lg hover:bg-orange-600 transition-colors">
                    العودة للرئيسية
                  </a>
                </div>
              </div>
            </Route>
          </Switch>
        </Router>
      </CartProvider>
    </AuthProvider>
  );
}

export default App;