import bcrypt from 'bcrypt'; // تم التعديل هنا
import { randomUUID } from 'crypto';
import { dbStorage } from './db';

export class AuthService {
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }
  async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }
  async loginAdmin(email: string, password: string): Promise<{ success: boolean; token?: string; userType?: string; message?: string }> {
    try {
      const admin = await dbStorage.getAdminByEmail(email);
      if (!admin) return { success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' };
      if (!admin.isActive) return { success: false, message: 'الحساب غير مفعل' };
      const isPasswordValid = await this.verifyPassword(password, admin.password);
      if (!isPasswordValid) return { success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' };
      const token = randomUUID();
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24);
      const sessionData: InsertAdminSession = {
        adminId: admin.id,
        token,
        userType: admin.userType,
        expiresAt
      };
      await dbStorage.createAdminSession(sessionData);
      return { success: true, token, userType: admin.userType };
    } catch (error) {
      console.error('خطأ في تسجيل الدخول:', error);
      return { success: false, message: 'حدث خطأ في الخادم' };
    }
  }
  async validateSession(token: string): Promise<{ valid: boolean; userType?: string; adminId?: string }> {
    try {
      const session = await dbStorage.getAdminSession(token);
      if (!session) return { valid: false };
      if (new Date() > session.expiresAt) {
        await dbStorage.deleteAdminSession(token);
        return { valid: false };
      }
      return { valid: true, userType: session.userType, adminId: session.adminId || undefined };
    } catch (error) {
      console.error('خطأ في التحقق من الجلسة:', error);
      return { valid: false };
    }
  }
  async logout(token: string): Promise<boolean> {
    try {
      return await dbStorage.deleteAdminSession(token);
    } catch (error) {
      console.error('خطأ في تسجيل الخروج:', error);
      return false;
    }
  }
  async createDefaultAdmin(): Promise<void> {
    try {
      const existingAdmin = await dbStorage.getAdminByEmail('admin@alsarie-one.com');
      if (!existingAdmin) {
        const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123456';
        const hashedPassword = await this.hashPassword(adminPassword);
        const defaultAdmin: InsertAdminUser = {
          name: 'مدير النظام',
          email: 'admin@alsarie-one.com',
          password: hashedPassword,
          userType: 'admin'
        };
        await dbStorage.createAdminUser(defaultAdmin);
        console.log('تم إنشاء المدير الافتراضي بنجاح');
      }
    } catch (error) {
      console.error('خطأ في إنشاء المدير الافتراضي:', error);
    }
  }
}
export const authService = new AuthService();