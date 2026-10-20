import Link from "next/link";
import { useI18n } from "@/lib/i18n";

export function BrandMark({ variant = "compact" }: { variant?: "home" | "compact" }) {
  const { t } = useI18n();
  return (
    <Link href="/" className={`brand brand-${variant}`} aria-label={t("home")}>
      <span className="brand-mark" aria-hidden="true">
        {variant === "home" && <span className="brand-mark-corner" />}
      </span>
      <span className="brand-text">Whoice</span>
    </Link>
  );
}
