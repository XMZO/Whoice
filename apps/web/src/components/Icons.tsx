import type { ReactNode } from "react";

type IconProps = {
  size?: number;
  className?: string;
};

function Svg({ size = 16, className, children, strokeWidth = 1.5 }: IconProps & { children: ReactNode; strokeWidth?: number }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {children}
    </svg>
  );
}

export const SearchIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.6}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="m10.5 10.5 3 3" />
  </Svg>
);

export const CheckCircleIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.8}>
    <circle cx="8" cy="8" r="6.25" />
    <path d="m5.25 8.25 1.9 1.9 3.6-3.9" />
  </Svg>
);

export const WarnIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.6}>
    <path d="M8 2.25 14.25 13.5H1.75z" />
    <path d="M8 6.75v3" />
    <path d="M8 11.75v.01" />
  </Svg>
);

export const CopyIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.4}>
    <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
    <path d="M10.5 3.5V3A1.5 1.5 0 0 0 9 1.5H4A1.5 1.5 0 0 0 2.5 3v5A1.5 1.5 0 0 0 4 9.5h.5" />
  </Svg>
);

export const LinkIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2.1-2.1a2.75 2.75 0 0 0-3.9-3.9l-.7.7M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2.1 2.1a2.75 2.75 0 0 0 3.9 3.9l.7-.7" />
  </Svg>
);

export const FileIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.4}>
    <path d="M4 1.75h5.25l3 3v9.5H4z M9 1.75V5h3.25 M6 8h4.5 M6 10.5h4.5" />
  </Svg>
);

export const DownloadIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M8 2v8m-3.25-3.25L8 10l3.25-3.25M2.75 13.5h10.5" />
  </Svg>
);

export const ImageIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.4}>
    <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" />
    <circle cx="5.75" cy="6.25" r="1.25" />
    <path d="m14.25 10.5-3.5-3.25-6.5 6" />
  </Svg>
);

export const BuildingIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M3 14V2.75h6.5V14" />
    <path d="M9.5 6.25H13V14" />
    <path d="M1.75 14h12.5" />
    <path d="M5.25 5.25h1.5M5.25 8h1.5M5.25 10.75h1.5" />
  </Svg>
);

export const CalendarIcon = (props: IconProps) => (
  <Svg {...props}>
    <rect x="2" y="3" width="12" height="11" rx="1.5" />
    <path d="M2 6.5h12M5 1.75v2.5M11 1.75v2.5" />
  </Svg>
);

export const ClockIcon = (props: IconProps) => (
  <Svg {...props}>
    <circle cx="8" cy="8" r="6.25" />
    <path d="M8 4.75V8l2.25 1.5" />
  </Svg>
);

export const RefreshIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M13.25 6.5A5.5 5.5 0 0 0 3 5M2.75 9.5A5.5 5.5 0 0 0 13 11" />
    <path d="M3 2.25V5h2.75M13 13.75V11h-2.75" />
  </Svg>
);

export const ShieldIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M8 1.75 13 3.5v4c0 3.2-2.1 5.6-5 6.75C5.1 13.1 3 10.7 3 7.5v-4z" />
    <path d="m5.75 8 1.6 1.6 3.15-3.1" />
  </Svg>
);

export function LockIcon({ size = 11, className }: IconProps) {
  return (
    <svg aria-hidden="true" className={className} width={size} height={size} viewBox="0 0 16 16">
      <rect x="3" y="7" width="10" height="7" rx="1.5" fill="currentColor" />
      <path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

export const GlobeIcon = (props: IconProps) => (
  <Svg {...props}>
    <circle cx="8" cy="8" r="6.25" />
    <path d="M1.75 8h12.5M8 1.75c1.8 1.7 2.7 3.8 2.7 6.25S9.8 12.55 8 14.25C6.2 12.55 5.3 10.45 5.3 8S6.2 3.45 8 1.75z" />
  </Svg>
);

export const TagIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M2.25 2.25h5.5l6 6-5.5 5.5-6-6z" />
    <circle cx="5.25" cy="5.25" r="1" />
  </Svg>
);

export const UserIcon = (props: IconProps) => (
  <Svg {...props}>
    <circle cx="8" cy="5.5" r="2.75" />
    <path d="M2.75 13.75c.6-2.6 2.7-4 5.25-4s4.65 1.4 5.25 4" />
  </Svg>
);

export const TerminalIcon = (props: IconProps) => (
  <Svg {...props}>
    <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" />
    <path d="m4.5 6.25 2 1.75-2 1.75M8.5 10h3" />
  </Svg>
);

export const ExternalIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.6}>
    <path d="M6.5 3.5h-3v9h9v-3M9 3h4v4M13 3 7.5 8.5" />
  </Svg>
);

export const CloseIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.7}>
    <path d="m3.5 3.5 9 9M12.5 3.5l-9 9" />
  </Svg>
);

export const ScanIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M2.5 5.5c1.2-1.9 3.2-3 5.5-3s4.3 1.1 5.5 3M2.5 10.5c1.2 1.9 3.2 3 5.5 3s4.3-1.1 5.5-3M4.75 8h6.5" />
  </Svg>
);

export const ServerIcon = (props: IconProps) => (
  <Svg {...props}>
    <rect x="2" y="2.5" width="12" height="4.5" rx="1.25" />
    <rect x="2" y="9" width="12" height="4.5" rx="1.25" />
    <path d="M4.75 4.75h.01M4.75 11.25h.01" />
  </Svg>
);

export const PadlockIcon = (props: IconProps) => (
  <Svg {...props}>
    <rect x="3" y="7" width="10" height="7" rx="1.5" />
    <path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" />
  </Svg>
);

export const SparkIcon = (props: IconProps) => (
  <Svg {...props}>
    <path d="M8 1.75v3M8 11.25v3M1.75 8h3M11.25 8h3M3.6 3.6l2 2M10.4 10.4l2 2M3.6 12.4l2-2M10.4 5.6l2-2" />
  </Svg>
);

export const ArrowRightIcon = (props: IconProps) => (
  <Svg {...props} strokeWidth={1.7}>
    <path d="M3 8h10M9 4l4 4-4 4" />
  </Svg>
);

export const NetworkIcon = (props: IconProps) => (
  <Svg {...props}>
    <rect x="5.75" y="1.75" width="4.5" height="3.5" rx="0.75" />
    <rect x="1.75" y="10.75" width="4.5" height="3.5" rx="0.75" />
    <rect x="9.75" y="10.75" width="4.5" height="3.5" rx="0.75" />
    <path d="M8 5.25v2.5M4 10.75V7.75h8v3" />
  </Svg>
);
