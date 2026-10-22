import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { CSSProperties, FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { BuildingIcon, FileIcon, GlobeIcon, PadlockIcon, ScanIcon, SearchIcon, ServerIcon, ShieldIcon, SparkIcon, TagIcon, TerminalIcon } from "@/components/Icons";
import { appendLookupOptions, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { readHistory, writeHistory, type HistoryItem } from "@/lib/history";
import { useI18n, type I18nKey } from "@/lib/i18n";
import { describeInput, detectInputKind, kindLabel, relativeTime } from "@/lib/resultModel";

type SourceMode = "all" | "rdap" | "whois";
type RunState = "idle" | "running" | "done";

type AdvancedState = {
  rdapServer: string;
  whoisServer: string;
  whoisFollow: string;
  exactDomain: boolean;
  forceAI: boolean;
};

const EXAMPLES = ["github.com", "1.1.1.1", "AS13335", "2606:4700::/32"];

function sourceParams(mode: SourceMode) {
  const params = new URLSearchParams();
  if (mode === "rdap") params.set("rdap", "1");
  if (mode === "whois") params.set("whois", "1");
  return params;
}

function advancedOptions(value: AdvancedState): LookupOptions {
  return {
    rdapServer: value.rdapServer.trim(),
    whoisServer: value.whoisServer.trim(),
    whoisFollow: value.whoisFollow,
    exactDomain: value.exactDomain ? "1" : undefined,
    ai: value.forceAI ? "1" : undefined,
  };
}

function delay(seconds: number) {
  return { "--rise-delay": `${seconds}s` } as CSSProperties;
}

function SourceToggle({ value, onChange }: { value: SourceMode; onChange: (value: SourceMode) => void }) {
  const { t } = useI18n();
  const options: { value: SourceMode; label: string }[] = [
    { value: "all", label: t("sourceAll") },
    { value: "rdap", label: t("sourceRdapOnly") },
    { value: "whois", label: t("sourceWhoisOnly") },
  ];

  return (
    <div className="source-toggle" role="radiogroup" aria-label={t("lookupSource")}>
      {options.map((option) => (
        <button
          key={option.value}
          aria-checked={value === option.value}
          className={value === option.value ? "source-option active" : "source-option"}
          onClick={() => onChange(option.value)}
          role="radio"
          type="button"
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function useNarrowScreen() {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(max-width: 760px)");
    const update = () => setNarrow(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return narrow;
}

// Types the example queries into the empty search box, one character at a time.
function useTypingDemo(active: boolean) {
  const [frame, setFrame] = useState({ demo: 0, chars: 0, hold: 8, erasing: false });
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    if (!active || reduced) return;
    const timer = window.setInterval(() => {
      setFrame((current) => {
        const text = EXAMPLES[current.demo];
        if (current.hold > 0) return { ...current, hold: current.hold - 1 };
        if (!current.erasing) {
          return current.chars < text.length ? { ...current, chars: current.chars + 1 } : { ...current, erasing: true, hold: 30 };
        }
        if (current.chars > 0) return { ...current, chars: current.chars - 1 };
        return { demo: (current.demo + 1) % EXAMPLES.length, chars: 0, hold: 6, erasing: false };
      });
    }, 75);
    return () => window.clearInterval(timer);
  }, [active, reduced]);

  const example = EXAMPLES[frame.demo];
  return { example, text: reduced ? example : example.slice(0, frame.chars), reduced };
}

const FLOW_ICONS = [<ScanIcon key="scan" />, <BuildingIcon key="building" />, <TerminalIcon key="terminal" />, <ShieldIcon key="shield" />];
const FLOW_TITLES: I18nKey[] = ["flowStep1", "flowStep2", "flowStep3", "flowStep4"];

const FEATURES: { icon: ReactNode; title: I18nKey; desc: I18nKey }[] = [
  { icon: <ServerIcon />, title: "feat1Title", desc: "feat1Desc" },
  { icon: <GlobeIcon />, title: "feat2Title", desc: "feat2Desc" },
  { icon: <PadlockIcon />, title: "feat3Title", desc: "feat3Desc" },
  { icon: <TagIcon />, title: "feat4Title", desc: "feat4Desc" },
  { icon: <FileIcon />, title: "feat5Title", desc: "feat5Desc" },
  { icon: <SparkIcon />, title: "feat6Title", desc: "feat6Desc" },
];

export default function HomePage() {
  const router = useRouter();
  const { t, tf } = useI18n();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [now, setNow] = useState(0);
  const [sourceMode, setSourceMode] = useState<SourceMode>("all");
  const [advanced, setAdvanced] = useState<AdvancedState>({
    rdapServer: "",
    whoisServer: "",
    whoisFollow: "",
    exactDomain: false,
    forceAI: false,
  });
  const [run, setRun] = useState<RunState>("idle");
  const [step, setStep] = useState(0);
  const demo = useTypingDemo(!query);
  const narrow = useNarrowScreen();
  const typed = query.trim();
  const info = useMemo(() => describeInput(typed || demo.example, t, tf), [demo.example, t, tf, typed]);

  useEffect(() => {
    setHistory(readHistory());
    setNow(Date.now());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      const tag = (event.target as HTMLElement | null)?.tagName;
      if (event.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
        event.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // The API does not stream progress, so the flow advances on route events:
  // step 1 is local, steps 2-3 play while the result page loads.
  useEffect(() => {
    if (run !== "running") return;
    const timer = window.setTimeout(() => setStep((current) => Math.max(current, 2)), 650);
    const onError = () => {
      setRun("idle");
      setStep(0);
    };
    const onDone = () => {
      setStep(4);
      setRun("done");
    };
    router.events.on("routeChangeError", onError);
    router.events.on("routeChangeComplete", onDone);
    return () => {
      window.clearTimeout(timer);
      router.events.off("routeChangeError", onError);
      router.events.off("routeChangeComplete", onDone);
    };
  }, [router.events, run]);

  // Text typed before the page hydrated is in the input but not in state.
  useEffect(() => {
    const typed = inputRef.current?.value || "";
    if (typed) setQuery(typed);
  }, []);

  function updateQuery(value: string) {
    setQuery(value);
    if (run !== "running") {
      setRun("idle");
      setStep(0);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const value = normalizeLookupInput(query);
    if (!value) {
      inputRef.current?.focus();
      return;
    }
    setQuery(value);
    writeHistory(value);
    setRun("running");
    setStep(1);
    const params = sourceParams(sourceMode);
    params.set("query", value);
    appendLookupOptions(params, advancedOptions(advanced));
    void router.push(`/lookup?${params.toString()}`);
  }

  function nodeState(index: number) {
    if (run === "idle") return "idle";
    if (run === "done" || step > index) return "passed";
    if (step === index) return "current";
    return "waiting";
  }

  const statusText = run === "running" ? `${t("flowRunning")} · ${Math.min(step + 1, 4)}/4` : run === "done" ? t("flowDone") : t("flowIdle");

  const exampleButtons = (
    <>
      {EXAMPLES.map((example) => (
        <button type="button" key={example} className="example-chip lift" onClick={() => updateQuery(example)}>
          <span className="kind-tag">{kindLabel(detectInputKind(example), t)}</span>
          <span className="mono">{example}</span>
        </button>
      ))}
    </>
  );

  const checks = (
    <>
      <label className="inline-check" title={t("exactDomainHint")}>
        <input type="checkbox" checked={advanced.exactDomain} onChange={(event) => setAdvanced((current) => ({ ...current, exactDomain: event.target.checked }))} />
        <span>{t("exactDomain")}</span>
      </label>
      <label className="inline-check" title={t("forceAIHint")}>
        <input type="checkbox" checked={advanced.forceAI} onChange={(event) => setAdvanced((current) => ({ ...current, forceAI: event.target.checked }))} />
        <span>{t("forceAI")}</span>
      </label>
    </>
  );

  return (
    <>
      <Head>
        <title>Whoice</title>
        <meta name="description" content={t("siteDescription")} />
        <meta property="og:title" content="Whoice" />
        <meta property="og:image" content="/api/og" />
        <meta name="twitter:card" content="summary_large_image" />
      </Head>
      <main className="home-shell">
        <div className="home-bg-dots" aria-hidden="true" />
        <div className="home-bg-glow" aria-hidden="true" />
        <div className="home-bg-glow-2" aria-hidden="true" />

        <div className="home-inner">
          <header className="home-topbar">
            <BrandMark variant="home" />
            <nav className="home-nav" aria-label={t("siteNav")}>
              <Link href="/docs">{t("docs")}</Link>
              <Link href="/status">{t("status")}</Link>
              <a href="https://github.com/XMZO/Whoice" target="_blank" rel="noreferrer">GitHub</a>
              <Link href="/admin">{t("adminPanel")}</Link>
              <AppControls />
            </nav>
            <a className="home-github-mobile" href="https://github.com/XMZO/Whoice" target="_blank" rel="noreferrer">GitHub</a>
          </header>

          <section className="search-hero" aria-label={t("lookup")}>
            <form className="lookup-form rise" onSubmit={submit}>
              <div className="search-ring">
                <span className="search-ring-light" aria-hidden="true" />
                <div className="search-box">
                  <SearchIcon size={18} className="search-box-icon" />
                  <span className="search-input-wrap">
                    <input
                      id="whoice-search"
                      ref={inputRef}
                      autoFocus
                      autoComplete="off"
                      autoCapitalize="none"
                      autoCorrect="off"
                      enterKeyHint="search"
                      value={query}
                      onChange={(event) => updateQuery(event.target.value)}
                      aria-label={t("placeholder")}
                      spellCheck={false}
                    />
                    {!query && (
                      <span className="search-demo" aria-hidden="true">
                        {demo.text}
                        {!demo.reduced && <span className="search-caret" />}
                      </span>
                    )}
                  </span>
                  <kbd className="search-kbd" aria-hidden="true">/</kbd>
                  <button type="submit">{t("search")}</button>
                </div>
              </div>
            </form>

            <div className="detect-row rise" style={delay(0.08)} aria-live="polite">
              <span className="detect-lead">{typed ? t("homeDetected") : t("homeExample")}</span>
              <span className="detect-type" key={`type-${info.label}`}>{info.label}</span>
              <span className="detect-route" key={`route-${info.route}`}>{info.route}</span>
            </div>

            <div className="home-options rise" style={delay(0.16)}>
              <SourceToggle value={sourceMode} onChange={setSourceMode} />
              <span className="home-checks">{checks}</span>
            </div>

            <div className="advanced-lookup rise" style={delay(0.22)}>
              <span className="row-caption">{t("customServers")}</span>
              <input
                className="server-input server-rdap"
                aria-label={t("rdapServer")}
                placeholder={narrow ? t("rdapServer") : "RDAP  https://rdap.example"}
                value={advanced.rdapServer}
                onChange={(event) => setAdvanced((current) => ({ ...current, rdapServer: event.target.value }))}
                spellCheck={false}
              />
              <input
                className="server-input server-whois"
                aria-label={t("whoisServer")}
                placeholder={narrow ? t("whoisServer") : "WHOIS  whois.example:43"}
                value={advanced.whoisServer}
                onChange={(event) => setAdvanced((current) => ({ ...current, whoisServer: event.target.value }))}
                spellCheck={false}
              />
              <input
                className="server-input server-follow"
                aria-label={t("whoisFollow")}
                placeholder={narrow ? t("followDepthShort") : t("followDepth")}
                type="number"
                min="0"
                max="5"
                value={advanced.whoisFollow}
                onChange={(event) => setAdvanced((current) => ({ ...current, whoisFollow: event.target.value }))}
              />
            </div>

            <div className="example-row rise" style={delay(0.28)}>
              <span className="row-caption">{t("examples")}</span>
              {exampleButtons}
            </div>
          </section>

          <section className="flow-card rise" style={delay(0.34)} aria-labelledby="h-flow">
            <div className="flow-head">
              <h2 id="h-flow">{t("flowTitle")}</h2>
              <span className="flow-status" role="status" data-run={run}>
                <span className="flow-status-dot" aria-hidden="true" />
                {statusText}
              </span>
            </div>
            <ol className="flow-grid">
              {FLOW_TITLES.map((title, index) => (
                <li className="flow-step" key={title}>
                  <div className="flow-track">
                    <span className="flow-node" data-state={nodeState(index)}>{FLOW_ICONS[index]}</span>
                    {index < 3 && (
                      <span className="flow-conn" aria-hidden="true" data-passed={run === "done" || (run === "running" && step > index)}>
                        {run === "running" && step === index && <span className="flow-stream" />}
                      </span>
                    )}
                  </div>
                  <span className="flow-index">0{index + 1}</span>
                  <strong>{t(title)}</strong>
                  <span className="flow-detail flow-detail-full" key={`full-${info.steps[index].full}`}>{info.steps[index].full}</span>
                  <span className="flow-detail flow-detail-short" key={`short-${info.steps[index].short}`}>{info.steps[index].short}</span>
                </li>
              ))}
            </ol>
          </section>

          <div className="home-bottom">
            <section className="home-section" aria-labelledby="h-recent">
              <div className="home-section-head">
                <h2 id="h-recent">{t("recent")}</h2>
                <span>{t("localOnly")}</span>
              </div>
              {history.length === 0 ? (
                <div className="recent-empty">
                  <span className="muted">{t("emptyHistory")}</span>
                  <div className="example-row">{exampleButtons}</div>
                </div>
              ) : (
                <div className="recent-grid">
                  {history.slice(0, 6).map((item, index) => (
                    <Link
                      key={`${item.query}-${item.timestamp}`}
                      href={`/lookup?query=${encodeURIComponent(item.query)}`}
                      className="recent-card lift"
                      style={delay(0.4 + index * 0.06)}
                    >
                      <span className="recent-card-top">
                        <span className="kind-tag">{kindLabel(item.type, t)}</span>
                        <span className="recent-when">{now ? relativeTime(item.timestamp, now, tf, t) : ""}</span>
                      </span>
                      <span className="recent-query">{item.query}</span>
                    </Link>
                  ))}
                </div>
              )}
            </section>

            <section className="home-section home-features" aria-labelledby="h-features">
              <div className="home-section-head">
                <h2 id="h-features">{t("features")}</h2>
              </div>
              <div className="feature-grid">
                {FEATURES.map((feature, index) => (
                  <div className="feature-card lift" key={feature.title} style={delay(0.5 + index * 0.06)}>
                    <span className="icon-tile" aria-hidden="true">{feature.icon}</span>
                    <span className="feature-text">
                      <strong>{t(feature.title)}</strong>
                      <span>{t(feature.desc)}</span>
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>

        <div className="home-mobile-bar">
          {checks}
          <span className="spacer" />
          <Link href="/docs">{t("docs")}</Link>
          <Link href="/status">{t("status")}</Link>
          <AppControls />
        </div>
      </main>
    </>
  );
}
