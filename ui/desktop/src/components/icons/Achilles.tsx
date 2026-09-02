import { cn } from '../../utils';

const LAMBDA_PATH = 'M40 4L76 80l3 10H63L40 44 17 90H1l3-10L40 4z';

export function AchillesLambda({ className = '' }: { className?: string }) {
  return (
    <svg
      aria-hidden
      viewBox="1 4 78 86"
      className={cn('overflow-visible', className)}
      fill="currentColor"
    >
      <path d={LAMBDA_PATH} />
    </svg>
  );
}

/** In-app mark: same lambda as the window / tray icon. */
export function Achilles({ className = '' }: { className?: string }) {
  return <AchillesLambda className={cn('block', className)} />;
}

/** Inscription wordmark — Cinzel with a solid Odyssey-style Lambda. */
export function AchillesWordmark({
  className = '',
  markOnly = false,
}: {
  className?: string;
  markOnly?: boolean;
}) {
  if (markOnly) {
    return (
      <span className={cn('inline-flex items-center font-mark', className)} aria-label="Achilles">
        <AchillesLambda className="block h-[1em] w-auto" />
      </span>
    );
  }

  return (
    <span className={cn('font-mark font-bold uppercase leading-none', className)} aria-label="Achilles">
      <AchillesLambda className="mr-[0.14em] inline-block h-[1.12em] w-auto align-baseline" />
      <span aria-hidden="true" className="tracking-[0.14em]">
        CHILLES
      </span>
    </span>
  );
}
