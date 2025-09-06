import express from "express";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { db } from "./db.js";
import { adminRoutes } from "./routes/admin.js";
import { customerRoutes } from "./routes/customer.js";
import { driverRoutes } from "./routes/driver.js";
import { publicRoutes } from "./routes/public.js";
import { setupVite, serveStatic } from "./vite.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// إعداد CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// API Routes
app.use('/api/admin', adminRoutes);
app.use('/api/customer', customerRoutes);
app.use('/api/driver', driverRoutes);
app.use('/api', publicRoutes);

// إعداد Vite أو الملفات الثابتة
if (process.env.NODE_ENV === "development") {
  await setupVite(app);
} else {
  serveStatic(app);
}

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`);
  console.log(`📱 تطبيق العملاء: http://localhost:${PORT}`);
  console.log(`🏢 لوحة التحكم: http://localhost:${PORT}/admin`);
  console.log(`🚚 تطبيق السائقين: http://localhost:${PORT}/delivery`);
});

// معالجة الأخطاء
process.on('uncaughtException', (error) => {
  console.error('خطأ غير معالج:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('رفض غير معالج في:', promise, 'السبب:', reason);
});