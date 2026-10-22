export function Seal({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.3">
      <circle cx="16" cy="16" r="13" />
      <path d="M16 6c4.6 2.6 4.6 5.4 10 10-5.4 4.6-5.4 7.4-10 10-4.6-2.6-4.6-5.4-10-10C11.4 11.4 11.4 8.6 16 6z" />
      <circle cx="16" cy="16" r="4.5" />
    </svg>
  );
}
