import { AchillesWordmark } from './icons';
import { cn } from '../utils';

interface GooseLogoProps {
  className?: string;
  size?: 'default' | 'small';
  hover?: boolean;
}

export default function GooseLogo({
  className = '',
  size = 'default',
  hover = true,
}: GooseLogoProps) {
  const sizes = {
    default: {
      frame: 'w-16 h-16',
      mark: 'text-[2.75rem]',
    },
    small: {
      frame: 'w-8 h-8',
      mark: 'text-2xl',
    },
  } as const;

  const currentSize = sizes[size];

  return (
    <div
      className={cn(
        className,
        currentSize.frame,
        'relative overflow-hidden flex items-center justify-center',
        hover && 'group/with-hover'
      )}
    >
      <AchillesWordmark
        markOnly
        className={cn(currentSize.mark, 'text-text-primary', hover && 'transition-opacity')}
      />
    </div>
  );
}
