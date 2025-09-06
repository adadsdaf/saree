import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Edit, Trash2, Package, Save, X, DollarSign, Tag } from 'lucide-react';
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
import type { MenuItem, Restaurant } from '@shared/schema';

export default function AdminMenuItems() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [editingItem, setEditingItem] = useState<MenuItem | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [selectedRestaurant, setSelectedRestaurant] = useState<string>('');
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    price: '',
    originalPrice: '',
    image: '',
    category: '',
    isAvailable: true,
    isSpecialOffer: false,
    restaurantId: '',
  });

  const { data: restaurants } = useQuery<Restaurant[]>({
    queryKey: ['/api/restaurants'],
  });

  const { data: menuItems, isLoading } = useQuery<MenuItem[]>({
    queryKey: ['/api/restaurants', selectedRestaurant, 'menu'],
    enabled: !!selectedRestaurant,
  });

  const createMenuItemMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const submitData = {
        ...data,
        price: parseFloat(data.price),
        originalPrice: data.originalPrice ? parseFloat(data.originalPrice) : null,
      };
      const response = await apiRequest('POST', '/api/menu-items', submitData);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants', selectedRestaurant, 'menu'] });
      toast({
        title: "تم إضافة الوجبة",
        description: "تم إضافة الوجبة الجديدة بنجاح",
      });
      resetForm();
      setIsDialogOpen(false);
    },
  });

  const updateMenuItemMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: typeof formData }) => {
      const submitData = {
        ...data,
        price: parseFloat(data.price),
        originalPrice: data.originalPrice ? parseFloat(data.originalPrice) : null,
      };
      const response = await apiRequest('PUT', `/api/menu-items/${id}`, submitData);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants', selectedRestaurant, 'menu'] });
      toast({
        title: "تم تحديث الوجبة",
        description: "تم تحديث الوجبة بنجاح",
      });
      resetForm();
      setEditingItem(null);
      setIsDialogOpen(false);
    },
  });

  const deleteMenuItemMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest('DELETE', `/api/menu-items/${id}`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/restaurants', selectedRestaurant, 'menu'] });
      toast({
        title: "تم حذف الوجبة",
        description: "تم حذف الوجبة بنجاح",
      });
    },
  });

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      price: '',
      originalPrice: '',
      image: '',
      category: '',
      isAvailable: true,
      isSpecialOffer: false,
      restaurantId: selectedRestaurant,
    });
    setEditingItem(null);
  };

  const handleEdit = (item: MenuItem) => {
    setEditingItem(item);
    setFormData({
      name: item.name,
      description: item.description || '',
      price: item.price,
      originalPrice: item.originalPrice || '',
      image: item.image,
      category: item.category,
      isAvailable: item.isAvailable,
      isSpecialOffer: item.isSpecialOffer,
      restaurantId: item.restaurantId || '',
    });
    setIsDialogOpen(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.name.trim() || !formData.price || !selectedRestaurant) {
      toast({
        title: "خطأ",
        description: "يرجى إدخال جميع البيانات المطلوبة",
        variant: "destructive",
      });
      return;
    }

    const dataWithRestaurant = { ...formData, restaurantId: selectedRestaurant };

    if (editingItem) {
      updateMenuItemMutation.mutate({ id: editingItem.id, data: dataWithRestaurant });
    } else {
      createMenuItemMutation.mutate(dataWithRestaurant);
    }
  };

  const toggleItemStatus = (item: MenuItem, field: 'isAvailable' | 'isSpecialOffer') => {
    updateMenuItemMutation.mutate({
      id: item.id,
      data: { ...formData, [field]: !item[field] }
    });
  };

  const menuCategories = [
    'وجبات رمضان',
    'المشروبات',
    'الحلويات',
    'الوجبات الرئيسية',
    'المقبلات',
    'السلطات',
    'العروض',
    'أخرى'
  ];

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
          <Package className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold text-foreground">إدارة قوائم الطعام</h1>
            <p className="text-muted-foreground">إدارة الوجبات والمنتجات</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <Select value={selectedRestaurant} onValueChange={setSelectedRestaurant}>
            <SelectTrigger className="w-48" data-testid="select-restaurant">
              <SelectValue placeholder="اختر مطعم" />
            </SelectTrigger>
            <SelectContent>
              {restaurants?.map((restaurant) => (
                <SelectItem key={restaurant.id} value={restaurant.id}>
                  {restaurant.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button 
                className="gap-2"
                onClick={() => {
                  resetForm();
                  setIsDialogOpen(true);
                }}
                disabled={!selectedRestaurant}
                data-testid="button-add-menu-item"
              >
                <Plus className="h-4 w-4" />
                إضافة وجبة
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>
                  {editingItem ? 'تعديل الوجبة' : 'إضافة وجبة جديدة'}
                </DialogTitle>
              </DialogHeader>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="name">اسم الوجبة</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="أدخل اسم الوجبة"
                    required
                    data-testid="input-menu-item-name"
                  />
                </div>

                <div>
                  <Label htmlFor="description">وصف الوجبة</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="وصف مفصل للوجبة ومكوناتها"
                    rows={3}
                    data-testid="input-menu-item-description"
                  />
                </div>

                <div>
                  <Label htmlFor="image">رابط صورة الوجبة</Label>
                  <Input
                    id="image"
                    value={formData.image}
                    onChange={(e) => setFormData(prev => ({ ...prev, image: e.target.value }))}
                    placeholder="https://example.com/food-image.jpg"
                    required
                    data-testid="input-menu-item-image"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="category">قسم الوجبة</Label>
                    <Select value={formData.category} onValueChange={(value) => setFormData(prev => ({ ...prev, category: value }))}>
                      <SelectTrigger data-testid="select-menu-item-category">
                        <SelectValue placeholder="اختر قسم الوجبة" />
                      </SelectTrigger>
                      <SelectContent>
                        {menuCategories.map((category) => (
                          <SelectItem key={category} value={category}>
                            {category}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="price">السعر (ريال)</Label>
                    <Input
                      id="price"
                      type="number"
                      min="0"
                      step="0.01"
                      value={formData.price}
                      onChange={(e) => setFormData(prev => ({ ...prev, price: e.target.value }))}
                      placeholder="0.00"
                      required
                      data-testid="input-menu-item-price"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="originalPrice">السعر الأصلي (للعروض)</Label>
                  <Input
                    id="originalPrice"
                    type="number"
                    min="0"
                    step="0.01"
                    value={formData.originalPrice}
                    onChange={(e) => setFormData(prev => ({ ...prev, originalPrice: e.target.value }))}
                    placeholder="السعر قبل الخصم (اختياري)"
                    data-testid="input-menu-item-original-price"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="isAvailable">متوفر</Label>
                    <Switch
                      id="isAvailable"
                      checked={formData.isAvailable}
                      onCheckedChange={(checked) => setFormData(prev => ({ ...prev, isAvailable: checked }))}
                      data-testid="switch-menu-item-available"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="isSpecialOffer">عرض خاص</Label>
                    <Switch
                      id="isSpecialOffer"
                      checked={formData.isSpecialOffer}
                      onCheckedChange={(checked) => setFormData(prev => ({ ...prev, isSpecialOffer: checked }))}
                      data-testid="switch-menu-item-special-offer"
                    />
                  </div>
                </div>

                <div className="flex gap-2 pt-4">
                  <Button 
                    type="submit" 
                    className="flex-1 gap-2"
                    disabled={createMenuItemMutation.isPending || updateMenuItemMutation.isPending}
                    data-testid="button-save-menu-item"
                  >
                    <Save className="h-4 w-4" />
                    {editingItem ? 'تحديث' : 'إضافة'}
                  </Button>
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => {
                      resetForm();
                      setIsDialogOpen(false);
                    }}
                    data-testid="button-cancel-menu-item"
                  >
                    <X className="h-4 w-4" />
                    إلغاء
                  </Button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Restaurant Selection Message */}
      {!selectedRestaurant && (
        <Card>
          <CardContent className="p-8 text-center">
            <Package className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">اختر مطعم</h3>
            <p className="text-muted-foreground">يرجى اختيار مطعم من القائمة أعلاه لعرض وإدارة قائمة الطعام</p>
          </CardContent>
        </Card>
      )}

      {/* Menu Items Grid */}
      {selectedRestaurant && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {isLoading ? (
            [...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <div className="w-full h-48 bg-muted" />
                <CardContent className="p-4">
                  <div className="h-4 bg-muted rounded w-3/4 mb-2" />
                  <div className="h-3 bg-muted rounded w-1/2" />
                </CardContent>
              </Card>
            ))
          ) : menuItems?.length ? (
            menuItems.map((item) => (
              <Card key={item.id} className="hover:shadow-md transition-shadow overflow-hidden">
                <div className="w-full h-48 bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                  {item.image ? (
                    <img 
                      src={item.image} 
                      alt={item.name}
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <Package className="h-16 w-16 text-primary/50" />
                  )}
                </div>
                
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-lg mb-2">{item.name}</CardTitle>
                      <Badge variant="secondary" className="mb-2">
                        {item.category}
                      </Badge>
                      {item.description && (
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {item.description}
                        </p>
                      )}
                    </div>
                    <div className="flex flex-col gap-1">
                      <Badge variant={item.isAvailable ? "default" : "outline"}>
                        {item.isAvailable ? 'متوفر' : 'غير متوفر'}
                      </Badge>
                      {item.isSpecialOffer && (
                        <Badge className="bg-green-500">عرض خاص</Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  <div className="text-center">
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-bold text-primary">
                        {parseDecimal(item.price)} ريال
                      </span>
                      {item.originalPrice && (
                        <span className="text-sm text-muted-foreground line-through">
                          {parseDecimal(item.originalPrice)} ريال
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div className="text-center">
                      <p className="text-xs text-muted-foreground">متوفر</p>
                      <Switch
                        checked={item.isAvailable}
                        onCheckedChange={() => toggleItemStatus(item, 'isAvailable')}
                        data-testid={`switch-item-available-${item.id}`}
                      />
                    </div>
                    <div className="text-center">
                      <p className="text-xs text-muted-foreground">عرض خاص</p>
                      <Switch
                        checked={item.isSpecialOffer}
                        onCheckedChange={() => toggleItemStatus(item, 'isSpecialOffer')}
                        data-testid={`switch-item-special-${item.id}`}
                      />
                    </div>
                  </div>

                  <div className="flex gap-2 pt-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1 gap-2"
                      onClick={() => handleEdit(item)}
                      data-testid={`button-edit-menu-item-${item.id}`}
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
                          data-testid={`button-delete-menu-item-${item.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>تأكيد الحذف</AlertDialogTitle>
                          <AlertDialogDescription>
                            هل أنت متأكد من حذف الوجبة "{item.name}"؟ 
                            لن تظهر في قائمة المطعم بعد الحذف.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>إلغاء</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => deleteMenuItemMutation.mutate(item.id)}
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
          ) : selectedRestaurant ? (
            <div className="col-span-full text-center py-12">
              <Package className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">لا توجد وجبات</h3>
              <p className="text-muted-foreground mb-4">ابدأ بإضافة وجبات لهذا المطعم</p>
              <Button onClick={() => setIsDialogOpen(true)} data-testid="button-add-first-menu-item">
                إضافة الوجبة الأولى
              </Button>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}