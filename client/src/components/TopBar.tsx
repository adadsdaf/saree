import React, { useState } from 'react';
import { useLocation } from 'wouter';
import { useToast } from '@/hooks/use-toast';
import { 
  ShoppingCart, 
  Search,
  Clock,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { useCart } from '../context/CartContext';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { useUiSettings } from '@/context/UiSettingsContext';
import { CustomerNotificationsPanel } from './CustomerNotificationsPanel';

// ─── Working Hours Strip ─────────────────────────────────────────────────────
const WorkingHoursStrip: React.FC = () => {
  const { getSetting } = useUiSettings();
  const storeStatus = getSetting('store_status') || 'auto';
  const openingTime = getSetting('opening_time') || '08:00';
  const closingTime = getSetting('closing_time') || '23:00';

  const computeIsOpen = (): boolean => {
    if (storeStatus === 'open') return true;
    if (storeStatus === 'closed') return false;
    const now = new Date();
    const currentMinutes = now.getHours() * 60 + now.getMinutes();
    const toMin = (t: string) => {
      const [h, m] = t.split(':').map(Number);
      return (h || 0) * 60 + (m || 0);
    };
    const open = toMin(openingTime);
    const close = toMin(closingTime);
    if (close > open) return currentMinutes >= open && currentMinutes < close;
    return currentMinutes >= open || currentMinutes < close;
  };

  const [isOpen, setIsOpen] = React.useState(computeIsOpen);

  React.useEffect(() => {
    setIsOpen(computeIsOpen());
    const t = setInterval(() => setIsOpen(computeIsOpen()), 60000);
    return () => clearInterval(t);
  }, [storeStatus, openingTime, closingTime]);

  return (
    <div
      className="bg-white flex items-center justify-between gap-2 px-4 py-2 border-b border-gray-100"
      data-testid="indicator-working-hours"
    >
      <span
        className={`text-[11px] font-black px-2.5 py-0.5 rounded-full shrink-0 ${
          isOpen
            ? 'bg-green-500 text-white'
            : 'bg-primary text-white'
        }`}
      >
        {isOpen ? 'مفتوح' : 'مغلق'}
      </span>
      <div className="flex items-center gap-1.5 text-xs text-gray-600 font-medium">
        <Clock className="h-3.5 w-3.5 text-gray-400 shrink-0" />
        <span>
          أوقات الدوام من الساعة {openingTime} حتى {closingTime}
        </span>
      </div>
    </div>
  );
};

// ─── TopBar ──────────────────────────────────────────────────────────────────
export const TopBar: React.FC = () => {
  const [, setLocation] = useLocation();
  const { state } = useCart();
  const { user } = useAuth();
  const { t, language, setLanguage } = useLanguage();
  const { toast } = useToast();
  const { getSetting, loading: settingsLoading } = useUiSettings();
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const logoUrl = getSetting('header_logo_url') || getSetting('logo_url') || '';
  const appName = getSetting('app_name') || 'واصل';
  const appTagline = getSetting('app_tagline') || 'دوماً في خدمتك';

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      setLocation(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
      setIsSearchOpen(false);
    }
  };

  const handleOpenCart = () => {
    window.dispatchEvent(new CustomEvent('openCart'));
  };

  const getItemCount = () => state.items.reduce((sum, item) => sum + item.quantity, 0);

  return (
    <div className="sticky top-0 z-50">

      {/* ── Desktop Header ─────────────────────────────────────────────────── */}
      <div className="hidden md:block bg-primary shadow-md">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between gap-6">

          {/* Logo + App name */}
          <div
            className="flex items-center gap-3 cursor-pointer shrink-0"
            onClick={() => setLocation('/')}
            data-testid="link-home-logo"
          >
            {logoUrl ? (
              <img src={logoUrl} alt={appName} className="h-12 w-auto object-contain" />
            ) : (
              <div className="text-2xl font-black text-white tracking-tight">{appName}</div>
            )}
            {logoUrl && (
              <div className="flex flex-col leading-none">
                <span className="text-xl font-black text-white">{appName}</span>
                <span className="text-[10px] font-medium text-white/70 mt-0.5">{appTagline}</span>
              </div>
            )}
          </div>

          {/* Search Bar */}
          <div className="flex-1 max-w-xl">
            <form onSubmit={handleSearch} className="relative">
              <Input
                className="w-full pr-4 pl-10 h-10 bg-white/95 border-0 rounded-xl text-sm font-medium placeholder:text-gray-400"
                placeholder={t('search_placeholder') || 'ابحث عن مطعم أو طبق...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <button type="submit" className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-primary transition-colors">
                <Search className="h-4.5 w-4.5" />
              </button>
            </form>
          </div>

          {/* Right icons */}
          <div className="flex items-center gap-2">
            <CustomerNotificationsPanel />
            <button
              onClick={handleOpenCart}
              className="relative h-10 w-10 flex items-center justify-center text-white hover:bg-white/20 rounded-full transition-colors"
              aria-label="cart"
            >
              <ShoppingCart className="h-5 w-5 text-amber-300" />
              {getItemCount() > 0 && (
                <span className="absolute top-0.5 right-0.5 bg-amber-400 text-primary text-[9px] rounded-full h-4 min-w-4 px-0.5 flex items-center justify-center font-black">
                  {getItemCount()}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* ── Mobile Header ──────────────────────────────────────────────────── */}
      <div className="md:hidden">
        {/* Main header bar - solid red */}
        <div className="bg-primary px-4 py-3 flex items-center justify-between">

          {/* RIGHT (RTL start): Logo + App name + tagline */}
          <div
            className="flex items-center gap-2.5 cursor-pointer"
            onClick={() => setLocation('/')}
            data-testid="link-home-logo-mobile"
          >
            {logoUrl && (
              <div className="w-10 h-10 rounded-xl overflow-hidden bg-white/20 flex items-center justify-center shrink-0">
                <img src={logoUrl} alt={appName} className="w-full h-full object-contain" />
              </div>
            )}
            <div className="flex flex-col leading-none">
              <span className="text-white font-black text-xl tracking-tight leading-tight">
                {settingsLoading ? '...' : appName}
              </span>
              <span className="text-white/75 text-[11px] font-medium mt-0.5 leading-tight">
                {appTagline}
              </span>
            </div>
          </div>

          {/* LEFT (RTL end): Search, Notifications, Cart */}
          <div className="flex items-center gap-0.5">
            <button
              onClick={() => setIsSearchOpen(!isSearchOpen)}
              className="h-10 w-10 flex items-center justify-center text-white hover:bg-white/20 rounded-full transition-colors"
              aria-label="search"
            >
              <Search className="h-5 w-5" />
            </button>

            {/* Notifications bell */}
            <div className="[&_button]:text-white [&_button]:hover:bg-white/20 [&_button]:rounded-full [&_svg]:stroke-white">
              <CustomerNotificationsPanel />
            </div>

            {/* Cart */}
            <button
              onClick={handleOpenCart}
              className="h-10 w-10 flex items-center justify-center relative hover:bg-white/20 rounded-full transition-colors"
              aria-label="cart"
            >
              <ShoppingCart className="h-5 w-5 text-amber-300" />
              {getItemCount() > 0 && (
                <span className="absolute top-1 right-1 bg-amber-400 text-primary text-[9px] rounded-full h-4 min-w-4 px-0.5 flex items-center justify-center font-black ring-2 ring-primary">
                  {getItemCount()}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Working Hours Strip */}
        <WorkingHoursStrip />

        {/* Expandable Search Bar */}
        {isSearchOpen && (
          <div className="bg-white px-3 pb-3 pt-2 border-b border-gray-100">
            <form onSubmit={handleSearch} className="relative">
              <input
                autoFocus
                className="w-full bg-gray-100 text-slate-900 placeholder-gray-400 rounded-xl px-4 py-2.5 pl-11 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary/30"
                placeholder="ابحث عن مطعم أو طبق..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <button
                type="submit"
                className="absolute left-3 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full bg-primary text-white flex items-center justify-center"
              >
                <Search className="h-3.5 w-3.5" />
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};

export default TopBar;
