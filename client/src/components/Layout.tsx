import { useState, useEffect } from 'react';
import { useLocation } from 'wouter';
import { Home, Search, Receipt, User, ShoppingCart, Moon, Sun, Menu, X, Settings, Shield, MapPin, Clock, Truck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet';
import { useTheme } from '../context/ThemeContext';
import { useCart } from '../context/CartContext';
import CartButton from './CartButton';
import { useToast } from '@/hooks/use-toast';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const [location, setLocation] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const { getItemCount } = useCart();
  const { toast } = useToast();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [logoClickCount, setLogoClickCount] = useState(0);
  const [showAdminButtons, setShowAdminButtons] = useState(false);
  
  // States for profile click counter
  const [profileClickCount, setProfileClickCount] = useState(0);
  const [lastProfileClickTime, setLastProfileClickTime] = useState(0);

  const isHomePage = location === '/';
  const isAdminPage = location.startsWith('/admin');
  const isDeliveryPage = location.startsWith('/delivery');

  const navigationItems = [
    { icon: Home, label: 'الرئيسية', path: '/', testId: 'nav-home' },
    { icon: Search, label: 'البحث', path: '/search', testId: 'nav-search' },
    { icon: Receipt, label: 'طلباتي', path: '/orders', testId: 'nav-orders' },
    { icon: User, label: 'الملف الشخصي', path: '/profile', testId: 'nav-profile' },
  ];

  const sidebarMenuItems = [
    { icon: User, label: 'الملف الشخصي', path: '/profile', testId: 'sidebar-profile' },
    { icon: Receipt, label: 'طلباتي', path: '/orders', testId: 'sidebar-orders' },
    { icon: MapPin, label: 'العناوين المحفوظة', path: '/addresses', testId: 'sidebar-addresses' },
    { icon: Clock, label: 'تتبع الطلبات', path: '/orders', testId: 'sidebar-tracking' },
    { icon: Settings, label: 'الإعدادات', path: '/settings', testId: 'sidebar-settings' },
    { icon: Shield, label: 'سياسة الخصوصية', path: '/privacy', testId: 'sidebar-privacy' },
  ];

  // وظيفة التعامل مع النقر على أيقونة الملف الشخصي
  const handleProfileIconClick = () => {
    const currentTime = Date.now();
    
    // إذا مر أكثر من ثانيتين منذ آخر نقرة، نعيد العداد
    if (currentTime - lastProfileClickTime > 2000) {
      setProfileClickCount(1);
    } else {
      setProfileClickCount(prev => prev + 1);
    }
    
    setLastProfileClickTime(currentTime);

    // إذا وصل إلى 5 نقرات
    if (profileClickCount + 1 === 5) {
      toast({
        title: "الوصول إلى صفحة تسجيل الدخول",
        description: "سيتم الانتقال إلى صفحة تسجيل الدخول للإدارة",
      });
      
      // الانتقال إلى صفحة تسجيل الدخول
      window.location.href = '/admin-login';
      setProfileClickCount(0);
    } else if (profileClickCount + 1 > 2) {
      // إشعار بعد النقرات الأولى
      toast({
        title: `نقرة ${profileClickCount + 1} من 5`,
        description: "استمر للنقل للوصول إلى صفحة تسجيل الدخول",
      });
    }
  };

  // إعادة تعيين عداد النقرات بعد 2 ثانية
  useEffect(() => {
    if (profileClickCount > 0) {
      const timer = setTimeout(() => {
        setProfileClickCount(0);
      }, 2000);

      return () => clearTimeout(timer);
    }
  }, [profileClickCount, lastProfileClickTime]);

  return (
    <div className="max-w-md mx-auto bg-background min-h-screen shadow-xl relative">
      {/* Header */}
      <header className="bg-card border-b border-border p-4 sticky top-0 z-40">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Sheet open={sidebarOpen} onOpenChange={setSidebarOpen}>
              <SheetTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  data-testid="button-menu"
                >
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="w-80">
                <SheetHeader>
                  <SheetTitle className="text-right">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 bg-primary rounded-full flex items-center justify-center">
                        <User className="h-6 w-6 text-primary-foreground" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-foreground">مرحباً بك</h3>
                        <p className="text-sm text-muted-foreground">في تطبيق السريع ون</p>
                      </div>
                    </div>
                  </SheetTitle>
                </SheetHeader>
                
                <div className="mt-8 space-y-2">
                  {sidebarMenuItems.map((item) => {
                    const Icon = item.icon;
                    return (
                      <Button
                        key={item.path}
                        variant="ghost"
                        className="w-full justify-start gap-3 h-12"
                        onClick={() => {
                          setLocation(item.path);
                          setSidebarOpen(false);
                        }}
                        data-testid={item.testId}
                      >
                        <Icon className="h-5 w-5 text-primary" />
                        <span className="text-foreground">{item.label}</span>
                      </Button>
                    );
                  })}
                  
                  {/* أزرار المدير والسائقين - تظهر دائمًا */}
                  <div className="border-t border-border pt-4 mt-4">
                    <Button
                      variant="ghost"
                      className="w-full justify-start gap-3 h-12"
                      onClick={() => {
                        window.location.href = '/admin-login';
                        setSidebarOpen(false);
                      }}
                      data-testid="sidebar-admin"
                    >
                      <Settings className="h-5 w-5 text-blue-500" />
                      <span className="text-foreground">لوحة التحكم</span>
                    </Button>
                    
                    <Button
                      variant="ghost"
                      className="w-full justify-start gap-3 h-12"
                      onClick={() => {
                        window.location.href = '/admin-login?type=driver';
                        setSidebarOpen(false);
                      }}
                      data-testid="sidebar-delivery"
                    >
                      <Truck className="h-5 w-5 text-green-500" />
                      <span className="text-foreground">تطبيق السائقين</span>
                    </Button>
                  </div>
                </div>
              </SheetContent>
            </Sheet>
            <div 
              className="text-center cursor-pointer"
              onClick={() => {
                const newCount = logoClickCount + 1;
                setLogoClickCount(newCount);
                
                if (newCount === 4) {
                  setShowAdminButtons(true);
                  setLogoClickCount(0);
                  // الانتقال إلى صفحة تسجيل الدخول
                  window.location.href = '/admin-login';
                } else if (newCount > 4) {
                  setLogoClickCount(0);
                }
                
                // Reset counter after 3 seconds if not completed
                setTimeout(() => {
                  setLogoClickCount(0);
                }, 3000);
              }}
            >
              <h1 className="text-lg font-bold text-primary">السريع ون</h1>
              <p className="text-xs text-muted-foreground">توصيل سريع</p>
              {logoClickCount > 0 && logoClickCount < 4 && (
                <div className="flex justify-center mt-1">
                  {Array.from({ length: 4 }, (_, i) => (
                    <div
                      key={i}
                      className={`w-2 h-2 rounded-full mx-1 ${
                        i < logoClickCount ? 'bg-primary' : 'bg-gray-300'
                      }`}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleTheme}
              data-testid="button-theme-toggle"
            >
              {theme === 'dark' ? (
                <Sun className="h-5 w-5" />
              ) : (
                <Moon className="h-5 w-5" />
              )}
            </Button>
            
            {/* أيقونة الملف الشخصي مع خاصية النقر المتعدد */}
            <Button
              variant="ghost"
              size="icon"
              onClick={handleProfileIconClick}
              className="relative"
              title="النقر 5 مرات للوصول إلى صفحة تسجيل الدخول"
              data-testid="button-profile"
            >
              <User className="h-5 w-5" />
              
              {/* مؤشر بصري للنقرات */}
              {profileClickCount > 0 && (
                <div className="absolute -top-1 -right-1 w-4 h-4 bg-primary rounded-full text-xs text-white flex items-center justify-center">
                  {profileClickCount}
                </div>
              )}
            </Button>
          </div>
        </div>

        {/* Search Bar - only show on home page */}
        {isHomePage && (
          <div className="relative">
            <input
              type="text"
              placeholder="ابحث عن المطاعم والوجبات..."
              className="w-full bg-muted text-foreground placeholder-muted-foreground rounded-lg pr-12 pl-4 py-3 focus:outline-none focus:ring-2 focus:ring-primary"
              data-testid="input-search"
            />
            <Search className="absolute right-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="pb-20">
        {children}
      </main>

      {/* Bottom Navigation - hide on admin and delivery pages */}
      {!isAdminPage && !isDeliveryPage && (
        <nav className="fixed bottom-0 left-0 right-0 max-w-md mx-auto bg-card border-t border-border px-4 py-2">
          <div className="flex justify-around items-center">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = location === item.path;
              
              return (
                <Button
                  key={item.path}
                  variant="ghost"
                  className={`flex flex-col items-center gap-1 py-2 px-3 ${
                    isActive
                      ? 'text-primary'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                  onClick={() => setLocation(item.path)}
                  data-testid={item.testId}
                >
                  <Icon className="h-5 w-5" />
                  <span className="text-xs">{item.label}</span>
                </Button>
              );
            })}
          </div>
        </nav>
      )}

      {/* Floating Cart Button - hide on admin and delivery pages */}
      {getItemCount() > 0 && !isAdminPage && !isDeliveryPage && <CartButton />}
    </div>
  );
}