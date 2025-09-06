import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Edit, Trash2, Store, Save, X, Clock, Star, MapPin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';
import type { Restaurant, Category } from '@shared/schema';

export default function AdminRestaurants() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [editingRestaurant, setEditingRestaurant] = useState<Restaurant | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    image: '',
    address: '',
    openingTime: '08:00',
    closingTime: '23:00',
    deliveryTime: '',
    deliveryFee: '0',
    minimumOrder: '0',
    isOpen: true,
    categoryId: '',
  });

  const { data: restaurants, isLoading: restaurantsLoading } = useQuery<Restaurant[]>({
    queryKey: ['/api/restaurants'],
  });

  const { data: categories } = useQuery<Category[]>({
    queryKey: ['/api/categories'],
  });

  const createRestaurantMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await apiRequest('POST', '/api/restaurants', data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants'] });
      toast({
        title: "تم إضافة المطعم",
        description: "تم إضافة المطعم الجديد بنجاح",
      });
      resetForm();
      setIsDialogOpen(false);
    },
  });

  const updateRestaurantMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<typeof formData> }) => {
      const response = await apiRequest('PUT', `/api/restaurants/${id}`, data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants'] });
      toast({
        title: "تم تحديث المطعم",
        description: "تم تحديث بيانات المطعم بنجاح",
      });
      resetForm();
      setEditingRestaurant(null);
      setIsDialogOpen(false);
    },
  });

  const deleteRestaurantMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest('DELETE', `/api/restaurants/${id}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants'] });
      toast({
        title: "تم حذف المطعم",
        description: "تم حذف المطعم بنجاح",
      });
    },
  });

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      image: '',
      address: '',
      openingTime: '08:00',
      closingTime: '23:00',
      deliveryTime: '',
      deliveryFee: '0',
      minimumOrder: '0',
      isOpen: true,
      categoryId: '',
    });
    setEditingRestaurant(null);
  };

  const handleEdit = (restaurant: Restaurant) => {
    setEditingRestaurant(restaurant);
    setFormData({
      name: restaurant.name,
      description: restaurant.description || '',
      image: restaurant.image,
      address: restaurant.address || '',
      openingTime: restaurant.openingTime || '08:00',
      closingTime: restaurant.closingTime || '23:00',
      deliveryTime: restaurant.deliveryTime,
      deliveryFee: restaurant.deliveryFee || '0',
      minimumOrder: restaurant.minimumOrder || '0',
      isOpen: restaurant.isOpen,
      categoryId: restaurant.categoryId || '',
    });
    setIsDialogOpen(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.name.trim()) {
      toast({
        title: "خطأ",
        description: "يرجى إدخال اسم المطعم",
        variant: "destructive",
      });
      return;
    }

    if (editingRestaurant) {
      updateRestaurantMutation.mutate({ id: editingRestaurant.id, data: formData });
    } else {
      createRestaurantMutation.mutate(formData);
    }
  };

  const toggleRestaurantStatus = (restaurant: Restaurant, field: 'isOpen') => {
    updateRestaurantMutation.mutate({
      id: restaurant.id,
      data: { [field]: !restaurant[field] }
    });
  };

  const getCategoryName = (categoryId: string) => {
    const category = categories?.find(c => c.id === categoryId);
    return category?.name || 'غير محدد';
  };

  // دالة لتحويل القيم الرقمية من string إلى number للعرض
  const parseDecimal = (value: string | null): number => {
    if (!value) return 0;
    const num = parseFloat(value);
    return isNaN(num) ? 0 : num;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Store className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold text-foreground">إدارة المطاعم</h1>
            <p className="text-muted-foreground">إدارة المطاعم والمتاجر</p>
          </div>
        </div>
        
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button 
              className="gap-2"
              onClick={() => {
                resetForm();
                setIsDialogOpen(true);
              }}
              data-testid="button-add-restaurant"
            >
              <Plus className="h-4 w-4" />
              إضافة مطعم جديد
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>
                {editingRestaurant ? 'تعديل بيانات المطعم' : 'إضافة مطعم جديد'}
              </DialogTitle>
            </DialogHeader>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="name">اسم المطعم</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="أدخل اسم المطعم"
                    required
                    data-testid="input-restaurant-name"
                  />
                </div>

                <div>
                  <Label htmlFor="category">القسم</Label>
                  <Select value={formData.categoryId} onValueChange={(value) => setFormData(prev => ({ ...prev, categoryId: value }))}>
                    <SelectTrigger data-testid="select-restaurant-category">
                      <SelectValue placeholder="اختر قسم المطعم" />
                    </SelectTrigger>
                    <SelectContent>
                      {categories?.map((category) => (
                        <SelectItem key={category.id} value={category.id}>
                          {category.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div>
                <Label htmlFor="description">الوصف</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="وصف المطعم"
                  rows={3}
                  data-testid="input-restaurant-description"
                />
              </div>

              <div>
                <Label htmlFor="image">رابط الصورة</Label>
                <Input
                  id="image"
                  value={formData.image}
                  onChange={(e) => setFormData(prev => ({ ...prev, image: e.target.value }))}
                  placeholder="https://example.com/image.jpg"
                  required
                  data-testid="input-restaurant-image"
                />
              </div>

              <div>
                <Label htmlFor="address">عنوان المطعم</Label>
                <Textarea
                  id="address"
                  value={formData.address || ''}
                  onChange={(e) => setFormData(prev => ({ ...prev, address: e.target.value }))}
                  placeholder="العنوان الكامل للمطعم"
                  rows={2}
                  data-testid="input-restaurant-address"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="openingTime">وقت الفتح</Label>
                  <Input
                    id="openingTime"
                    type="time"
                    value={formData.openingTime || '08:00'}
                    onChange={(e) => setFormData(prev => ({ ...prev, openingTime: e.target.value }))}
                    data-testid="input-restaurant-opening-time"
                  />
                </div>

                <div>
                  <Label htmlFor="closingTime">وقت الإغلاق</Label>
                  <Input
                    id="closingTime"
                    type="time"
                    value={formData.closingTime || '23:00'}
                    onChange={(e) => setFormData(prev => ({ ...prev, closingTime: e.target.value }))}
                    data-testid="input-restaurant-closing-time"
                  />
                </div>

                <div>
                  <Label htmlFor="deliveryTime">وقت التوصيل</Label>
                  <Input
                    id="deliveryTime"
                    value={formData.deliveryTime}
                    onChange={(e) => setFormData(prev => ({ ...prev, deliveryTime: e.target.value }))}
                    placeholder="30-45 دقيقة"
                    required
                    data-testid="input-restaurant-delivery-time"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="deliveryFee">رسوم التوصيل (ريال)</Label>
                  <Input
                    id="deliveryFee"
                    type="number"
                    min="0"
                    step="0.01"
                    value={formData.deliveryFee}
                    onChange={(e) => setFormData(prev => ({ ...prev, deliveryFee: e.target.value }))}
                    data-testid="input-restaurant-delivery-fee"
                  />
                </div>

                <div>
                  <Label htmlFor="minimumOrder">الحد الأدنى للطلب (ريال)</Label>
                  <Input
                    id="minimumOrder"
                    type="number"
                    min="0"
                    step="0.01"
                    value={formData.minimumOrder}
                    onChange={(e) => setFormData(prev => ({ ...prev, minimumOrder: e.target.value }))}
                    data-testid="input-restaurant-minimum-order"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="isOpen">مفتوح للطلبات</Label>
                <Switch
                  id="isOpen"
                  checked={formData.isOpen}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, isOpen: checked }))}
                  data-testid="switch-restaurant-open"
                />
              </div>

              <div className="flex gap-2 pt-4">
                <Button 
                  type="submit" 
                  className="flex-1 gap-2"
                  disabled={createRestaurantMutation.isPending || updateRestaurantMutation.isPending}
                  data-testid="button-save-restaurant"
                >
                  <Save className="h-4 w-4" />
                  {editingRestaurant ? 'تحديث' : 'إضافة'}
                </Button>
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => {
                    resetForm();
                    setIsDialogOpen(false);
                  }}
                  data-testid="button-cancel-restaurant"
                >
                  <X className="h-4 w-4" />
                  إلغاء
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Restaurants Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {restaurantsLoading ? (
          [...Array(6)].map((_, i) => (
            <Card key={i} className="animate-pulse">
              <div className="w-full h-48 bg-muted" />
              <CardContent className="p-4">
                <div className="h-4 bg-muted rounded w-3/4 mb-2" />
                <div className="h-3 bg-muted rounded w-1/2" />
              </CardContent>
            </Card>
          ))
        ) : restaurants?.length ? (
          restaurants.map((restaurant) => (
            <Card key={restaurant.id} className="hover:shadow-md transition-shadow overflow-hidden">
              <div className="w-full h-48 bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                {restaurant.image ? (
                  <img 
                    src={restaurant.image} 
                    alt={restaurant.name}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <Store className="h-16 w-16 text-primary/50" />
                )}
              </div>
              
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="text-lg mb-2">{restaurant.name}</CardTitle>
                    <p className="text-sm text-muted-foreground mb-2">
                      {getCategoryName(restaurant.categoryId || '')}
                    </p>
                    {restaurant.description && (
                      <p className="text-xs text-muted-foreground line-clamp-2">
                        {restaurant.description}
                      </p>
                    )}
                  </div>
                  <Badge variant={restaurant.isOpen ? "default" : "outline"}>
                    {restaurant.isOpen ? 'مفتوح' : 'مغلق'}
                  </Badge>
                </div>
              </CardHeader>
              
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="flex items-center gap-1">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span>{restaurant.deliveryTime}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    توصيل: {parseDecimal(restaurant.deliveryFee)} ريال
                  </div>
                  <div className="text-xs text-muted-foreground">
                    أقل طلب: {parseDecimal(restaurant.minimumOrder)} ريال
                  </div>
                  {restaurant.rating && (
                    <div className="flex items-center gap-1">
                      <Star className="h-4 w-4 text-yellow-500" />
                      <span>{restaurant.rating}</span>
                    </div>
                  )}
                </div>

                <div className="text-center">
                  <p className="text-xs text-muted-foreground">مفتوح</p>
                  <Switch
                    checked={restaurant.isOpen}
                    onCheckedChange={() => toggleRestaurantStatus(restaurant, 'isOpen')}
                    data-testid={`switch-restaurant-open-${restaurant.id}`}
                  />
                </div>

                <div className="flex gap-2 pt-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex-1 gap-2"
                    onClick={() => handleEdit(restaurant)}
                    data-testid={`button-edit-restaurant-${restaurant.id}`}
                  >
                    <Edit className="h-4 w-4" />
                    تعديل
                  </Button>
                  
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button
                        variant="outline"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        data-testid={`button-delete-restaurant-${restaurant.id}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>تأكيد الحذف</AlertDialogTitle>
                        <AlertDialogDescription>
                          هل أنت متأكد من حذف مطعم "{restaurant.name}"؟ 
                          سيتم حذف جميع منتجات المطعم أيضاً.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>إلغاء</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => deleteRestaurantMutation.mutate(restaurant.id)}
                          className="bg-destructive hover:bg-destructive/90"
                        >
                          حذف
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          <div className="col-span-full text-center py-12">
            <Store className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">لا توجد مطاعم</h3>
            <p className="text-muted-foreground mb-4">ابدأ بإضافة المطاعم والمتاجر</p>
            <Button onClick={() => setIsDialogOpen(true)} data-testid="button-add-first-restaurant">
              إضافة المطعم الأول
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}