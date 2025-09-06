import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "../shared/schema.js";
import { eq, and } from "drizzle-orm";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL غير محدد في متغيرات البيئة");
}

// إنشاء اتصال قاعدة البيانات
const sql = neon(process.env.DATABASE_URL);
export const db = drizzle(sql, { schema });

// فئة إدارة قاعدة البيانات
export class DatabaseStorage {
  // Admin Users
  async getAdminByEmail(email: string) {
    return await db.query.adminUsers.findFirst({
      where: eq(schema.adminUsers.email, email)
    });
  }

  async createAdminUser(userData: schema.NewAdminUser) {
    const [admin] = await db.insert(schema.adminUsers)
      .values(userData)
      .returning();
    return admin;
  }

  async getDriverByPhone(phone: string) {
    return await db.query.adminUsers.findFirst({
      where: and(
        eq(schema.adminUsers.phone, phone),
        eq(schema.adminUsers.userType, "driver")
      )
    });
  }

  // Admin Sessions
  async createAdminSession(sessionData: schema.NewAdminSession) {
    const [session] = await db.insert(schema.adminSessions)
      .values(sessionData)
      .returning();
    return session;
  }

  async getAdminSession(token: string) {
    return await db.query.adminSessions.findFirst({
      where: eq(schema.adminSessions.token, token)
    });
  }

  async deleteAdminSession(token: string) {
    const result = await db.delete(schema.adminSessions)
      .where(eq(schema.adminSessions.token, token));
    return result.rowCount > 0;
  }

  // Categories
  async getCategories() {
    return await db.query.categories.findMany({
      where: eq(schema.categories.isActive, true),
      orderBy: [schema.categories.name]
    });
  }

  async createCategory(categoryData: schema.NewCategory) {
    const [category] = await db.insert(schema.categories)
      .values(categoryData)
      .returning();
    return category;
  }

  async updateCategory(id: string, updateData: Partial<schema.NewCategory>) {
    const [category] = await db.update(schema.categories)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.categories.id, id))
      .returning();
    return category;
  }

  async deleteCategory(id: string) {
    const result = await db.delete(schema.categories)
      .where(eq(schema.categories.id, id));
    return result.rowCount > 0;
  }

  // Restaurants
  async getRestaurants() {
    return await db.query.restaurants.findMany({
      orderBy: [schema.restaurants.name]
    });
  }

  async getRestaurant(id: string) {
    return await db.query.restaurants.findFirst({
      where: eq(schema.restaurants.id, id)
    });
  }

  async getRestaurantsByCategory(categoryId: string) {
    return await db.query.restaurants.findMany({
      where: eq(schema.restaurants.categoryId, categoryId),
      orderBy: [schema.restaurants.name]
    });
  }

  async createRestaurant(restaurantData: schema.NewRestaurant) {
    const [restaurant] = await db.insert(schema.restaurants)
      .values(restaurantData)
      .returning();
    return restaurant;
  }

  async updateRestaurant(id: string, updateData: Partial<schema.NewRestaurant>) {
    const [restaurant] = await db.update(schema.restaurants)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.restaurants.id, id))
      .returning();
    return restaurant;
  }

  async deleteRestaurant(id: string) {
    const result = await db.delete(schema.restaurants)
      .where(eq(schema.restaurants.id, id));
    return result.rowCount > 0;
  }

  // Menu Items
  async getMenuItems(restaurantId: string) {
    return await db.query.menuItems.findMany({
      where: eq(schema.menuItems.restaurantId, restaurantId),
      orderBy: [schema.menuItems.name]
    });
  }

  async createMenuItem(menuItemData: schema.NewMenuItem) {
    const [menuItem] = await db.insert(schema.menuItems)
      .values(menuItemData)
      .returning();
    return menuItem;
  }

  async updateMenuItem(id: string, updateData: Partial<schema.NewMenuItem>) {
    const [menuItem] = await db.update(schema.menuItems)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.menuItems.id, id))
      .returning();
    return menuItem;
  }

  async deleteMenuItem(id: string) {
    const result = await db.delete(schema.menuItems)
      .where(eq(schema.menuItems.id, id));
    return result.rowCount > 0;
  }

  // Orders
  async getOrders() {
    return await db.query.orders.findMany({
      orderBy: [schema.orders.createdAt]
    });
  }

  async getOrder(id: string) {
    return await db.query.orders.findFirst({
      where: eq(schema.orders.id, id)
    });
  }

  async getOrdersByRestaurant(restaurantId: string) {
    return await db.query.orders.findMany({
      where: eq(schema.orders.restaurantId, restaurantId),
      orderBy: [schema.orders.createdAt]
    });
  }

  async createOrder(orderData: schema.NewOrder) {
    const [order] = await db.insert(schema.orders)
      .values(orderData)
      .returning();
    return order;
  }

  async updateOrder(id: string, updateData: Partial<schema.NewOrder>) {
    const [order] = await db.update(schema.orders)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.orders.id, id))
      .returning();
    return order;
  }

  // Drivers
  async getDrivers() {
    return await db.query.adminUsers.findMany({
      where: eq(schema.adminUsers.userType, "driver"),
      orderBy: [schema.adminUsers.name]
    });
  }

  async getAvailableDrivers() {
    return await db.query.adminUsers.findMany({
      where: and(
        eq(schema.adminUsers.userType, "driver"),
        eq(schema.adminUsers.isActive, true)
      ),
      orderBy: [schema.adminUsers.name]
    });
  }

  async createDriver(driverData: schema.NewAdminUser) {
    const [driver] = await db.insert(schema.adminUsers)
      .values({ ...driverData, userType: "driver" })
      .returning();
    return driver;
  }

  async updateDriver(id: string, updateData: Partial<schema.NewAdminUser>) {
    const [driver] = await db.update(schema.adminUsers)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.adminUsers.id, id))
      .returning();
    return driver;
  }

  async deleteDriver(id: string) {
    const result = await db.delete(schema.adminUsers)
      .where(eq(schema.adminUsers.id, id));
    return result.rowCount > 0;
  }

  // Special Offers
  async getSpecialOffers() {
    return await db.query.specialOffers.findMany({
      orderBy: [schema.specialOffers.createdAt]
    });
  }

  async getActiveSpecialOffers() {
    return await db.query.specialOffers.findMany({
      where: eq(schema.specialOffers.isActive, true),
      orderBy: [schema.specialOffers.createdAt]
    });
  }

  async createSpecialOffer(offerData: schema.NewSpecialOffer) {
    const [offer] = await db.insert(schema.specialOffers)
      .values(offerData)
      .returning();
    return offer;
  }

  async updateSpecialOffer(id: string, updateData: Partial<schema.NewSpecialOffer>) {
    const [offer] = await db.update(schema.specialOffers)
      .set({ ...updateData, updatedAt: new Date() })
      .where(eq(schema.specialOffers.id, id))
      .returning();
    return offer;
  }

  async deleteSpecialOffer(id: string) {
    const result = await db.delete(schema.specialOffers)
      .where(eq(schema.specialOffers.id, id));
    return result.rowCount > 0;
  }

  // UI Settings
  async getUiSettings() {
    return await db.query.systemSettings.findMany({
      orderBy: [schema.systemSettings.key]
    });
  }

  async getUiSetting(key: string) {
    return await db.query.systemSettings.findFirst({
      where: eq(schema.systemSettings.key, key)
    });
  }

  async updateUiSetting(key: string, value: string) {
    const [setting] = await db.update(schema.systemSettings)
      .set({ value: { value }, updatedAt: new Date() })
      .where(eq(schema.systemSettings.key, key))
      .returning();
    return setting;
  }

  async createUiSetting(settingData: schema.NewSystemSettings) {
    const [setting] = await db.insert(schema.systemSettings)
      .values(settingData)
      .returning();
    return setting;
  }

  async deleteUiSetting(key: string) {
    const result = await db.delete(schema.systemSettings)
      .where(eq(schema.systemSettings.key, key));
    return result.rowCount > 0;
  }
}

// إنشاء مثيل من قاعدة البيانات
export const dbStorage = new DatabaseStorage();

// دالة تهيئة قاعدة البيانات
export async function initializeDatabase() {
  try {
    console.log("🔄 جاري تهيئة قاعدة البيانات...");
    
    // إنشاء مدير النظام الافتراضي
    const existingAdmin = await db.query.adminUsers.findFirst({
      where: eq(schema.adminUsers.email, "aymenpro124@gmail.com")
    });

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash("777146387", 10);
      await db.insert(schema.adminUsers).values({
        email: "aymenpro124@gmail.com",
        password: hashedPassword,
        name: "مدير النظام",
        userType: "admin",
        isActive: true,
      });
      console.log("✅ تم إنشاء مدير النظام الافتراضي");
    }

    // إنشاء سائق تجريبي
    const existingDriver = await db.query.adminUsers.findFirst({
      where: eq(schema.adminUsers.phone, "+967771234567")
    });

    if (!existingDriver) {
      const hashedPassword = await bcrypt.hash("password123", 10);
      await db.insert(schema.adminUsers).values({
        phone: "+967771234567",
        password: hashedPassword,
        name: "سائق تجريبي",
        userType: "driver",
        isActive: true,
      });
      console.log("✅ تم إنشاء السائق التجريبي");
    }

    // إنشاء التصنيفات الافتراضية
    const existingCategories = await db.query.categories.findMany();
    
    if (existingCategories.length === 0) {
      const defaultCategories = [
        {
          name: "المطاعم",
          nameEn: "Restaurants",
          description: "مطاعم متنوعة",
          icon: "fas fa-utensils",
          color: "#FF6B35"
        },
        {
          name: "الحلويات",
          nameEn: "Sweets",
          description: "حلويات ومعجنات",
          icon: "fas fa-candy-cane",
          color: "#FF6B35"
        },
        {
          name: "اللحوم",
          nameEn: "Meat",
          description: "لحوم طازجة",
          icon: "fas fa-drumstick-bite",
          color: "#FF6B35"
        },
        {
          name: "كل التصنيفات",
          nameEn: "All Categories",
          description: "جميع التصنيفات",
          icon: "fas fa-th-large",
          color: "#FF6B35"
        }
      ];

      await db.insert(schema.categories).values(defaultCategories);
      console.log("✅ تم إنشاء التصنيفات الافتراضية");
    }

    // إنشاء أقسام المطاعم الافتراضية
    const existingSections = await db.query.restaurantSections.findMany();
    
    if (existingSections.length === 0) {
      const defaultSections = [
        { name: "المضغوط", nameEn: "Grilled", icon: "🔥" },
        { name: "البروست", nameEn: "Fried Chicken", icon: "🍗" },
        { name: "المشروبات", nameEn: "Beverages", icon: "🥤" },
        { name: "السلطات", nameEn: "Salads", icon: "🥗" },
        { name: "الحلويات", nameEn: "Desserts", icon: "🍰" },
        { name: "المقبلات", nameEn: "Appetizers", icon: "🥙" }
      ];

      await db.insert(schema.restaurantSections).values(defaultSections);
      console.log("✅ تم إنشاء أقسام المطاعم الافتراضية");
    }

    // إعدادات النظام الافتراضية
    const existingSettings = await db.query.systemSettings.findMany();
    
    if (existingSettings.length === 0) {
      const defaultSettings = [
        {
          key: "app_name",
          value: { value: "السريع ون" },
          description: "اسم التطبيق",
          category: "general",
          isPublic: true
        },
        {
          key: "currency",
          value: { value: "YER" },
          description: "العملة المستخدمة",
          category: "general",
          isPublic: true
        },
        {
          key: "delivery_fee",
          value: { value: "500" },
          description: "رسوم التوصيل الافتراضية",
          category: "delivery",
          isPublic: true
        },
        {
          key: "minimum_order",
          value: { value: "1000" },
          description: "الحد الأدنى للطلب",
          category: "orders",
          isPublic: true
        },
        {
          key: "service_fee_percentage",
          value: { value: "5" },
          description: "نسبة رسوم الخدمة",
          category: "fees",
          isPublic: false
        },
        // إعدادات الواجهة
        {
          key: "show_categories",
          value: { value: "true" },
          description: "عرض تصنيفات المطاعم",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_search_bar",
          value: { value: "true" },
          description: "عرض شريط البحث",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_special_offers",
          value: { value: "true" },
          description: "عرض العروض الخاصة",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_ratings",
          value: { value: "true" },
          description: "عرض تقييمات المطاعم",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_delivery_time",
          value: { value: "true" },
          description: "عرض وقت التوصيل",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_minimum_order",
          value: { value: "true" },
          description: "عرض الحد الأدنى للطلب",
          category: "ui",
          isPublic: true
        },
        {
          key: "show_restaurant_description",
          value: { value: "true" },
          description: "عرض وصف المطعم",
          category: "ui",
          isPublic: true
        },
        {
          key: "enable_location_services",
          value: { value: "true" },
          description: "تفعيل خدمات الموقع",
          category: "ui",
          isPublic: true
        },
        // إعدادات السائق
        {
          key: "driver_show_earnings",
          value: { value: "true" },
          description: "عرض الأرباح للسائق",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_customer_info",
          value: { value: "true" },
          description: "عرض معلومات العميل",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_order_details",
          value: { value: "true" },
          description: "عرض تفاصيل الطلب",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_available_orders",
          value: { value: "true" },
          description: "عرض الطلبات المتاحة",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_auto_refresh",
          value: { value: "true" },
          description: "التحديث التلقائي للطلبات",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_status_toggle",
          value: { value: "true" },
          description: "عرض مفتاح تغيير الحالة",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_location_button",
          value: { value: "true" },
          description: "عرض زر تحديث الموقع",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_show_navigation_help",
          value: { value: "true" },
          description: "عرض مساعدة التنقل",
          category: "driver",
          isPublic: true
        },
        {
          key: "driver_notification_sound",
          value: { value: "true" },
          description: "تفعيل صوت الإشعارات",
          category: "driver",
          isPublic: true
        }
      ];

      await db.insert(schema.systemSettings).values(defaultSettings);
      console.log("✅ تم إنشاء إعدادات النظام الافتراضية");
    }

    console.log("✅ تم تهيئة قاعدة البيانات بنجاح");
    
  } catch (error) {
    console.error("❌ خطأ في تهيئة قاعدة البيانات:", error);
    throw error;
  }
}

// تشغيل التهيئة عند بدء التطبيق
initializeDatabase().catch(console.error);