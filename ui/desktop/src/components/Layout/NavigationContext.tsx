import React, {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { NAV_DIMENSIONS } from './constants';

/**
 * When the window shrinks below this many CSS pixels, collapse the sidebar.
 * First load always stays expanded — we only collapse on a downward resize
 * crossing. The user can re-expand via the menu button without us fighting
 * further resizes until they go below the threshold from above again.
 */
const NARROW_WINDOW_THRESHOLD = 700;

export const MIN_NAV_WIDTH = 160;
export const MAX_NAV_WIDTH = 400;

interface NavigationContextValue {
  isNavExpanded: boolean;
  setIsNavExpanded: (expanded: boolean) => void;
  navWidth: number;
  setNavWidth: (width: number) => void;
}

const NavigationContext = createContext<NavigationContextValue | null>(null);

export const useNavigationContext = () => {
  const context = useContext(NavigationContext);
  if (!context) {
    throw new Error('useNavigationContext must be used within NavigationProvider');
  }
  return context;
};

export const useNavigationContextSafe = () => {
  return useContext(NavigationContext);
};

interface NavigationProviderProps {
  children: ReactNode;
}

export const NavigationProvider: React.FC<NavigationProviderProps> = ({ children }) => {
  const [isNavExpanded, setIsNavExpanded] = useState(true);

  const [navWidth, setNavWidthState] = useState<number>(() => {
    const stored = localStorage.getItem('navigation_width');
    if (stored) {
      const parsed = parseInt(stored, 10);
      if (!isNaN(parsed) && parsed >= MIN_NAV_WIDTH && parsed <= MAX_NAV_WIDTH) {
        return parsed;
      }
    }
    return NAV_DIMENSIONS.NAV_WIDTH;
  });

  const setNavWidth = useCallback((width: number) => {
    const clamped = Math.min(MAX_NAV_WIDTH, Math.max(MIN_NAV_WIDTH, width));
    setNavWidthState(clamped);
    localStorage.setItem('navigation_width', String(clamped));
  }, []);

  const isNavExpandedRef = useRef(isNavExpanded);
  useEffect(() => {
    isNavExpandedRef.current = isNavExpanded;
  }, [isNavExpanded]);

  useEffect(() => {
    const handleToggleNavigation = () => {
      setIsNavExpanded(!isNavExpandedRef.current);
    };
    window.electron.on('toggle-navigation', handleToggleNavigation);
    return () => {
      window.electron.off('toggle-navigation', handleToggleNavigation);
    };
  }, [setIsNavExpanded]);

  useEffect(() => {
    let lastWidth = window.innerWidth;
    const onResize = () => {
      const width = window.innerWidth;
      if (
        width < NARROW_WINDOW_THRESHOLD &&
        lastWidth >= NARROW_WINDOW_THRESHOLD &&
        isNavExpandedRef.current
      ) {
        setIsNavExpanded(false);
      }
      lastWidth = width;
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const value: NavigationContextValue = {
    isNavExpanded,
    setIsNavExpanded,
    navWidth,
    setNavWidth,
  };

  return <NavigationContext.Provider value={value}>{children}</NavigationContext.Provider>;
};
