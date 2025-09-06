import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useToast } from '@/hooks/use-toast';

interface User {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  userType: 'admin' | 'driver' | 'customer';
  token: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (identifier: string, password: string, userType: 'admin' | 'driver') => Promise<{ success: boolean; message?: string }>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  // تحقق من الجلسة المحفوظة عند تحميل التطبيق
  useEffect(() => {
    const checkStoredAuth = () => {
      try {
        const storedToken = localStorage.getItem('auth_token');
        const storedUser = localStorage.getItem('auth_user');
        
        if (storedToken && storedUser) {
          const userData = JSON.parse(storedUser);
          setUser({
            ...userData,
            token: storedToken
          });
        }
      } catch (error) {
        console.error('خطأ في استرداد بيانات المصادقة:', error);
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
      } finally {
        setIsLoading(false);
      }
    };

    checkStoredAuth();
  }, []);

  const login = async (identifier: string, password: string, userType: 'admin' | 'driver') => {
    try {
      setIsLoading(true);
      
      const endpoint = userType === 'admin' ? '/api/admin/login' : '/api/driver/login';
      const body = userType === 'admin' 
        ? { email: identifier, password }
        : { phone: identifier, password };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        const userData = {
          id: data[userType].id,
          name: data[userType].name,
          email: data[userType].email,
          phone: data[userType].phone,
          userType: userType,
          token: data.token
        };

        setUser(userData);
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('auth_user', JSON.stringify({
          id: userData.id,
          name: userData.name,
          email: userData.email,
          phone: userData.phone,
          userType: userData.userType
        }));

        toast({
          title: "تم تسجيل الدخول بنجاح",
          description: `مرحباً ${userData.name}`,
        });

        return { success: true };
      } else {
        return { 
          success: false, 
          message: data.error || 'فشل في تسجيل الدخول' 
        };
      }
    } catch (error) {
      console.error('خطأ في تسجيل الدخول:', error);
      return { 
        success: false, 
        message: 'حدث خطأ في الاتصال بالخادم' 
      };
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      if (user?.token) {
        const endpoint = user.userType === 'admin' ? '/api/admin/logout' : '/api/driver/logout';
        
        await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${user.token}`,
            'Content-Type': 'application/json',
          },
        });
      }
    } catch (error) {
      console.error('خطأ في تسجيل الخروج:', error);
    } finally {
      setUser(null);
      localStorage.removeItem('auth_token');
      localStorage.removeItem('auth_user');
      
      toast({
        title: "تم تسجيل الخروج",
        description: "تم تسجيل خروجك بنجاح",
      });
    }
  };

  const value = {
    user,
    isLoading,
    login,
    logout,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};