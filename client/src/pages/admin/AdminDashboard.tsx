<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة تحكم المشرف - تصحيح الأخطاء</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --primary-light: #bfdbfe;
            --primary-bg: #eff6ff;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-700: #374151;
            --gray-900: #111827;
            --red-500: #ef4444;
            --red-100: #fee2e2;
            --green-500: #22c55e;
            --green-100: #dcfce7;
            --orange-500: #f97316;
            --orange-100: #ffedd5;
            --purple-500: #a855f7;
            --purple-100: #f3e8ff;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background-color: var(--gray-50);
            color: var(--gray-900);
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: white;
            box-shadow: var(--shadow);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-radius: 12px;
            margin-bottom: 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(to bottom right, var(--primary), var(--primary-dark));
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }

        .auth-section {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .btn {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .btn-primary {
            background-color: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background-color: var(--primary-dark);
        }

        .btn-outline {
            background-color: transparent;
            border: 1px solid var(--primary);
            color: var(--primary);
        }

        .btn-outline:hover {
            background-color: var(--primary);
            color: white;
        }

        .btn-danger {
            background-color: var(--red-500);
            color: white;
        }

        .btn-danger:hover {
            background-color: #dc2626;
        }

        .debug-panel {
            background: white;
            border-radius: 12px;
            box-shadow: var(--shadow);
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .debug-panel h2 {
            color: var(--primary-dark);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--gray-200);
        }

        .debug-info {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .info-item {
            background: var(--gray-50);
            padding: 1rem;
            border-radius: 8px;
        }

        .info-item label {
            font-weight: 600;
            color: var(--gray-700);
            display: block;
            margin-bottom: 0.5rem;
        }

        .debug-actions {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .dashboard {
            display: grid;
            grid-template-columns: 250px 1fr;
            gap: 1.5rem;
        }

        .sidebar {
            background: white;
            border-radius: 12px;
            box-shadow: var(--shadow);
            padding: 1.5rem;
            height: fit-content;
        }

        .sidebar-menu {
            list-style: none;
        }

        .sidebar-menu li {
            margin-bottom: 0.5rem;
        }

        .sidebar-menu a {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            color: var(--gray-700);
            text-decoration: none;
            transition: all 0.3s ease;
        }

        .sidebar-menu a:hover, .sidebar-menu a.active {
            background-color: var(--primary-light);
            color: var(--primary);
        }

        .main-content {
            background: white;
            border-radius: 12px;
            box-shadow: var(--shadow);
            padding: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--gray-50);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
        }

        .stat-card i {
            font-size: 2rem;
            color: var(--primary);
            margin-bottom: 1rem;
        }

        .stat-card h3 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .tabs {
            margin-top: 2rem;
        }

        .tab-headers {
            display: flex;
            border-bottom: 1px solid var(--gray-200);
            margin-bottom: 1.5rem;
        }

        .tab-header {
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s ease;
        }

        .tab-header.active {
            border-bottom-color: var(--primary);
            color: var(--primary);
            font-weight: 600;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .api-response {
            background: var(--gray-100);
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 0.9rem;
        }

        .hidden {
            display: none;
        }

        .loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--gray-200);
            border-top: 4px solid var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 1rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            header {
                flex-direction: column;
                gap: 1rem;
            }
            
            .debug-info {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-chart-bar"></i>
                </div>
                <div class="logo-text">
                    <h2>لوحة تحكم المشرف - وضع التصحيح</h2>
                </div>
            </div>
            <div class="auth-section">
                <button class="btn btn-danger" onclick="logout()">تسجيل الخروج</button>
            </div>
        </header>

        <div class="debug-panel">
            <h2>معلومات التصحيح</h2>
            <div class="debug-info">
                <div class="info-item">
                    <label>حالة المصادقة:</label>
                    <span id="debugAuthStatus">غير معروف</span>
                </div>
                <div class="info-item">
                    <label>نوع المستخدم:</label>
                    <span id="debugUserType">غير معروف</span>
                </div>
                <div class="info-item">
                    <label>Token:</label>
                    <span id="debugToken">غير متوفر</span>
                </div>
                <div class="info-item">
                    <label>حالة طلب API:</label>
                    <span id="debugApiStatus">لم يتم الطلب بعد</span>
                </div>
                <div class="info-item">
                    <label>رابط API:</label>
                    <span>/api/admin/dashboard</span>
                </div>
                <div class="info-item">
                    <label>وقت آخر تحديث:</label>
                    <span id="debugLastUpdate">-</span>
                </div>
            </div>
            <div class="debug-actions">
                <button class="btn btn-primary" onclick="fetchDashboardData()">
                    <i class="fas fa-sync"></i> إعادة تحميل البيانات
                </button>
                <button class="btn btn-outline" onclick="simulateApiSuccess()">
                    <i class="fas fa-check-circle"></i> محاكاة استجابة ناجحة
                </button>
                <button class="btn btn-outline" onclick="simulateApiError()">
                    <i class="fas fa-exclamation-circle"></i> محاكاة خطأ في API
                </button>
                <button class="btn btn-outline" onclick="toggleJsonView()">
                    <i class="fas fa-code"></i> عرض/إخفاء JSON
                </button>
            </div>
            <div id="apiResponse" class="api-response hidden">
                {/* سيتم ملء هذا بالقسم dynamically */}
            </div>
        </div>

        <div id="loadingIndicator" class="loading">
            <div class="spinner"></div>
            <p>جاري تحميل بيانات لوحة التحكم...</p>
        </div>

        <div id="dashboardContent" class="hidden">
            <div class="dashboard">
                <div class="sidebar">
                    <h3 style="margin-bottom: 1rem;">القائمة</h3>
                    <ul class="sidebar-menu">
                        <li><a href="#" class="active"><i class="fas fa-tachometer-alt"></i> لوحة التحكم</a></li>
                        <li><a href="#"><i class="fas fa-shopping-bag"></i> الطلبات</a></li>
                        <li><a href="#"><i class="fas fa-store"></i> المطاعم</a></li>
                        <li><a href="#"><i class="fas fa-utensils"></i> قوائم الطعام</a></li>
                        <li><a href="#"><i class="fas fa-truck"></i> السائقين</a></li>
                        <li><a href="#"><i class="fas fa-tag"></i> العروض</a></li>
                        <li><a href="#"><i class="fas fa-users"></i> العملاء</a></li>
                        <li><a href="#"><i class="fas fa-cog"></i> الإعدادات</a></li>
                    </ul>
                </div>

                <div class="main-content">
                    <h2 style="margin-bottom: 1.5rem;">نظرة عامة على النظام</h2>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <i class="fas fa-shopping-bag"></i>
                            <h3 id="statOrders">0</h3>
                            <p>إجمالي الطلبات</p>
                        </div>
                        <div class="stat-card">
                            <i class="fas fa-users"></i>
                            <h3 id="statCustomers">0</h3>
                            <p>العملاء النشطين</p>
                        </div>
                        <div class="stat-card">
                            <i class="fas fa-dollar-sign"></i>
                            <h3 id="statRevenue">0 ريال</h3>
                            <p>إجمالي المبيعات</p>
                        </div>
                        <div class="stat-card">
                            <i class="fas fa-truck"></i>
                            <h3 id="statDrivers">0</h3>
                            <p>السائقين المتاحين</p>
                        </div>
                    </div>

                    <div class="tabs">
                        <div class="tab-headers">
                            <div class="tab-header active" onclick="switchTab('overview')">نظرة عامة</div>
                            <div class="tab-header" onclick="switchTab('orders')">الطلبات</div>
                            <div class="tab-header" onclick="switchTab('restaurants')">المطاعم</div>
                            <div class="tab-header" onclick="switchTab('drivers')">السائقين</div>
                        </div>

                        <div id="tabOverview" class="tab-content active">
                            <h3>الطلبات الحديثة</h3>
                            <div id="recentOrdersList">
                                <p>جاري تحميل البيانات...</p>
                            </div>
                        </div>

                        <div id="tabOrders" class="tab-content">
                            <h3>جميع الطلبات</h3>
                            <p>محتوى إدارة الطلبات سيظهر هنا</p>
                        </div>

                        <div id="tabRestaurants" class="tab-content">
                            <h3>المطاعم المسجلة</h3>
                            <p>محتوى إدارة المطاعم سيظهر هنا</p>
                        </div>

                        <div id="tabDrivers" class="tab-content">
                            <h3>السائقين المسجلين</h3>
                            <p>محتوى إدارة السائقين سيظهر هنا</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="errorContent" class="hidden" style="text-align: center; padding: 2rem;">
            <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: var(--red-500); margin-bottom: 1rem;"></i>
            <h2>فشل في تحميل بيانات لوحة التحكم</h2>
            <p id="errorMessage" style="margin-bottom: 1.5rem;">حدث خطأ أثناء محاولة تحميل البيانات</p>
            <button class="btn btn-primary" onclick="fetchDashboardData()">إعادة المحاولة</button>
        </div>
    </div>

    <script>
        // حالة التطبيق
        let authToken = localStorage.getItem('authToken') || 'fake-jwt-token-' + Math.random().toString(36).substring(2);
        let userType = localStorage.getItem('userType') || 'admin';
        let dashboardData = null;
        let lastUpdateTime = null;

        // عناصر DOM
        const loadingIndicator = document.getElementById('loadingIndicator');
        const dashboardContent = document.getElementById('dashboardContent');
        const errorContent = document.getElementById('errorContent');
        const apiResponseElement = document.getElementById('apiResponse');

        // عناصر التصحيح
        const debugAuthStatus = document.getElementById('debugAuthStatus');
        const debugUserType = document.getElementById('debugUserType');
        const debugToken = document.getElementById('debugToken');
        const debugApiStatus = document.getElementById('debugApiStatus');
        const debugLastUpdate = document.getElementById('debugLastUpdate');

        // تهيئة الصفحة
        function initPage() {
            updateDebugInfo();
            fetchDashboardData();
        }

        // تحديث معلومات التصحيح
        function updateDebugInfo() {
            debugAuthStatus.textContent = authToken ? 'مصادق' : 'غير مصادق';
            debugUserType.textContent = userType;
            debugToken.textContent = authToken ? authToken.substring(0, 20) + '...' : 'غير متوفر';
            debugLastUpdate.textContent = lastUpdateTime || '-';
        }

        // محاكاة استدعاء API
        function fetchDashboardData() {
            // إظهار مؤشر التحميل
            loadingIndicator.classList.remove('hidden');
            dashboardContent.classList.add('hidden');
            errorContent.classList.add('hidden');
            
            debugApiStatus.textContent = 'جاري التحميل...';
            updateDebugInfo();

            // محاكاة اتصال API مع الخادم
            setTimeout(() => {
                // في حالة نجاح محاكاة API
                if (Math.random() > 0.3) { // 70% فرصة نجاح
                    simulateApiSuccess();
                } else {
                    simulateApiError();
                }
            }, 2000);
        }

        // محاكاة استجابة API ناجحة
        function simulateApiSuccess() {
            // بيانات وهمية للوحة التحكم
            dashboardData = {
                stats: {
                    totalOrders: 1258,
                    totalCustomers: 524,
                    totalRevenue: 85420,
                    activeDrivers: 28,
                    todayOrders: 42,
                    todayRevenue: 3250,
                    pendingOrders: 12,
                    totalRestaurants: 36
                },
                recentOrders: [
                    { id: 1, orderNumber: '1001', customerName: 'أحمد محمد', total: 120, status: 'delivered', createdAt: new Date(Date.now() - 1000 * 60 * 15).toISOString() },
                    { id: 2, orderNumber: '1002', customerName: 'فاطمة علي', total: 85, status: 'preparing', createdAt: new Date(Date.now() - 1000 * 60 * 30).toISOString() },
                    { id: 3, orderNumber: '1003', customerName: 'خالد إبراهيم', total: 210, status: 'pending', createdAt: new Date(Date.now() - 1000 * 60 * 45).toISOString() },
                    { id: 4, orderNumber: '1004', customerName: 'سارة عبدالله', total: 65, status: 'ready', createdAt: new Date(Date.now() - 1000 * 60 * 60).toISOString() },
                    { id: 5, orderNumber: '1005', customerName: 'محمد حسن', total: 150, status: 'picked_up', createdAt: new Date(Date.now() - 1000 * 60 * 90).toISOString() }
                ]
            };

            // تحديث الوقت
            lastUpdateTime = new Date().toLocaleTimeString();
            
            // تحديث واجهة المستخدم
            updateDashboardUI();
            
            // تحديث حالة التصحيح
            debugApiStatus.textContent = 'نجح (200 OK)';
            updateDebugInfo();
            
            // إخفاء مؤشر التحميل وإظهار المحتوى
            loadingIndicator.classList.add('hidden');
            dashboardContent.classList.remove('hidden');
            
            // تحديث عرض JSON
            updateApiResponseView();
        }

        // محاكاة خطأ في API
        function simulateApiError() {
            // تحديث حالة التصحيح
            debugApiStatus.textContent = 'فشل (500 Internal Server Error)';
            lastUpdateTime = new Date().toLocaleTimeString();
            updateDebugInfo();
            
            // إخفاء مؤشر التحميل وإظهار رسالة الخطأ
            loadingIndicator.classList.add('hidden');
            errorContent.classList.remove('hidden');
            
            // تحديث عرض JSON
            apiResponseElement.textContent = '{\n  "error": "Internal Server Error",\n  "message": "حدث خطأ في الخادم",\n  "statusCode": 500\n}';
        }

        // تحديث واجهة لوحة التحكم
        function updateDashboardUI() {
            if (!dashboardData) return;
            
            // تحديث الإحصائيات
            document.getElementById('statOrders').textContent = dashboardData.stats.totalOrders.toLocaleString();
            document.getElementById('statCustomers').textContent = dashboardData.stats.totalCustomers.toLocaleString();
            document.getElementById('statRevenue').textContent = dashboardData.stats.totalRevenue.toLocaleString() + ' ريال';
            document.getElementById('statDrivers').textContent = dashboardData.stats.activeDrivers.toLocaleString();
            
            // تحديث قائمة الطلبات الحديثة
            const ordersList = document.getElementById('recentOrdersList');
            if (dashboardData.recentOrders.length > 0) {
                ordersList.innerHTML = '';
                dashboardData.recentOrders.forEach(order => {
                    const orderElement = document.createElement('div');
                    orderElement.style.padding = '0.75rem';
                    orderElement.style.border = '1px solid #e5e7eb';
                    orderElement.style.borderRadius = '0.5rem';
                    orderElement.style.marginBottom = '0.5rem';
                    orderElement.style.display = 'flex';
                    orderElement.style.justifyContent = 'space-between';
                    orderElement.style.alignItems = 'center';
                    
                    orderElement.innerHTML = `
                        <div>
                            <strong>طلب #${order.orderNumber}</strong>
                            <div>${order.customerName}</div>
                            <small>${new Date(order.createdAt).toLocaleString('ar-YE')}</small>
                        </div>
                        <div>
                            <span style="background: #e5e7eb; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.875rem;">
                                ${order.total} ريال
                            </span>
                        </div>
                    `;
                    
                    ordersList.appendChild(orderElement);
                });
            } else {
                ordersList.innerHTML = '<p>لا توجد طلبات حديثة</p>';
            }
        }

        // تحديث عرض استجابة API
        function updateApiResponseView() {
            if (dashboardData) {
                apiResponseElement.textContent = JSON.stringify(dashboardData, null, 2);
            }
        }

        // تبديل علامات التبويب
        function switchTab(tabName) {
            // إخفاء جميع المحتويات
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // إلغاء تنشيط جميع العناوين
            document.querySelectorAll('.tab-header').forEach(header => {
                header.classList.remove('active');
            });
            
            // إظهار المحتوى المحدد
            document.getElementById('tab' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
            
            // تنشيط العنوان المحدد
            document.querySelector(`.tab-header:nth-child(${['overview', 'orders', 'restaurants', 'drivers'].indexOf(tabName) + 1})`).classList.add('active');
        }

        // تبديل عرض JSON
        function toggleJsonView() {
            apiResponseElement.classList.toggle('hidden');
        }

        // تسجيل الخروج
        function logout() {
            localStorage.removeItem('authToken');
            localStorage.removeItem('userType');
            alert('تم تسجيل الخروج بنجاح');
            window.location.reload();
        }

        // بدء التطبيق
        initPage();
    </script>
</body>
</html>