import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import {
  ArrowLeft, ArrowRight, Building2, Eye, EyeOff, GraduationCap,
  HeartPulse, Landmark, LockKeyhole, LogOut, MonitorCog, RefreshCw,
  Shield, ShieldAlert, ShoppingBag, UserRound, Globe2,
} from 'lucide-react';

type Page = 'home' | 'login' | 'dashboard' | 'change-password';
type Domain = { id: string; name: string; abbr: string; org: string };
type User = { username: string; display_name: string; domain: string; must_change_password?: boolean };
type Customer = {
  reference: string; name: string; city: string; status: string;
  kindLabel: string; kind: string; detailLabel?: string; detail?: string;
  extraLabel: string; extra: string;
};

const knownDomains: Domain[] = [
  { id: 'business-services', name: 'Business Services', abbr: 'SMB', org: 'CivicShield Business Services' },
  { id: 'banking', name: 'Banking Services', abbr: 'BNK', org: 'CivicShield Banking Services' },
  { id: 'healthcare', name: 'Healthcare Services', abbr: 'HLT', org: 'CivicShield Health Services' },
  { id: 'education', name: 'Education Services', abbr: 'EDU', org: 'CivicShield Education Services' },
  { id: 'ecommerce', name: 'Online Shopping', abbr: 'SHOP', org: 'CivicShield Commerce Services' },
  { id: 'cybersecurity', name: 'Cyber Awareness Services', abbr: 'CYBER', org: 'CivicShield Cyber Awareness Services' },
  { id: 'government', name: 'Citizen Services', abbr: 'CIT', org: 'CivicShield Citizen Services' },
  { id: 'it-administration', name: 'IT Service Desk', abbr: 'IT', org: 'CivicShield IT Service Desk' },
];

const demoUserPrefixes: Record<string, string> = {
  'business-services': 'business', banking: 'bank', healthcare: 'health', education: 'education',
  ecommerce: 'shop', cybersecurity: 'cyber', government: 'citizen', 'it-administration': 'it',
};
const demoAccounts: Record<string, string[]> = Object.fromEntries(knownDomains.map(domain => [
  domain.id, Array.from({ length: 4 }, (_, index) => `${demoUserPrefixes[domain.id]}_user_${1001 + index}`),
]));
const demoPassword = 'ServiceDemo-2026!';
const icons = [Building2, Landmark, HeartPulse, GraduationCap, ShoppingBag, Shield, Globe2, MonitorCog];

async function api<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, { credentials: 'include', ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof payload.detail === 'string' ? payload.detail : payload.detail?.message || `Request failed (${response.status})`);
  return payload as T;
}

function domainIcon(index: number, size = 23) {
  const Icon = icons[index] || Building2;
  return <Icon size={size} strokeWidth={1.8} aria-hidden="true" />;
}

function Header({ page, user, onNavigate, onLogout }: {
  page: Page; user: User | null; onNavigate: (page: Page) => void; onLogout: () => void;
}) {
  return <>
    <div className="training-ribbon"><Shield size={15} /><b>FICTIONAL DEMONSTRATION</b><span>Sample service records only · Not a government service</span></div>
    <header className="portal-header">
      <button className="brand-button" onClick={() => onNavigate(user ? 'dashboard' : 'home')} aria-label="CivicShield home">
        <span className="brand-symbol"><Building2 size={24} /></span><span className="brand-text"><strong>UNIFIED DIGITAL SERVICES PORTAL</strong><small>CIVICSHIELD SERVICE DEMO</small></span>
      </button>
      <nav className="main-nav" aria-label="Main navigation"><button className={page === 'home' ? 'nav-active' : ''} onClick={() => onNavigate(user ? 'dashboard' : 'home')}>Services</button></nav>
      <div className="header-account">{user ? <><span className="signed-user"><UserRound size={15} />{user.display_name}</span><button className="logout-link" onClick={onLogout}><LogOut size={15} /> Sign out</button></> : <span className="secure-label"><LockKeyhole size={14} /> Customer sign-in</span>}</div>
    </header>
  </>;
}

function PortalAuth({ domain, onBack, onAuthenticated }: {
  domain: Domain; onBack: () => void; onAuthenticated: (user: User) => void;
}) {
  const [username, setUsername] = useState(demoAccounts[domain.id]?.[0] || '');
  const [password, setPassword] = useState(demoPassword);
  const [showPassword, setShowPassword] = useState(false);
  const [captcha, setCaptcha] = useState('');
  const [captchaChallengeId, setCaptchaChallengeId] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const refreshCaptcha = useCallback(async () => {
    try {
      const challenge = await api<{ challenge_id: string; code: string }>('/api/auth/captcha');
      setCaptchaChallengeId(challenge.challenge_id); setCaptcha(challenge.code); setCaptchaAnswer('');
    } catch { setCaptchaChallengeId(''); setError('Could not load the CAPTCHA. Refresh the page to try again.'); }
  }, []);
  useEffect(() => { void refreshCaptcha(); }, [refreshCaptcha]);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('');
    setBusy(true);
    try {
      const result = await api<{ user: User }>('/api/auth/login', {
        method: 'POST', body: JSON.stringify({ organization_domain: domain.id, username, password,
          captcha_challenge_id: captchaChallengeId, captcha_answer: captchaAnswer }),
      });
      onAuthenticated(result.user);
    } catch (issue) { setError((issue as Error).message); await refreshCaptcha(); }
    finally { setBusy(false); }
  };
  return <section className="auth-layout">
    <div className="auth-aside"><button className="back-button light-back" onClick={onBack}><ArrowLeft size={16} /> Back to services</button>
      <div className="domain-emblem">{domainIcon(knownDomains.findIndex(item => item.id === domain.id), 32)}</div>
      <div className="eyebrow light-eyebrow">CIVICSHIELD SERVICE PORTAL</div><h1>{domain.name}</h1><p>Sign in to the fictional {domain.org} demonstration.</p>
      <div className="demo-credential"><small>DEMO USER IDs</small><div className="demo-account-list">{(demoAccounts[domain.id] || []).map(account => <code key={account}>{account}</code>)}</div><small>DEMO PASSWORD</small><b>{demoPassword}</b><span>Each user account can view its own sample profile only. Do not enter real personal, financial, or health information.</span></div>
    </div>
    <div className="auth-card"><div className="auth-card-heading"><div className="eyebrow">CUSTOMER SIGN-IN</div><h2>Welcome back</h2><p>Sign in with your sample user ID to view your own service details.</p></div>
      <form onSubmit={submit} className="auth-form">
        <label>User ID<div className="input-with-icon"><UserRound size={16} /><input value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" required minLength={3} maxLength={48} placeholder="Enter your sample user ID" /></div></label>
        <label>Password<div className="input-with-icon"><LockKeyhole size={16} /><input value={password} onChange={event => setPassword(event.target.value)} type={showPassword ? 'text' : 'password'} autoComplete="current-password" required maxLength={256} /><button type="button" className="password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
        <div className="captcha-control"><div><label htmlFor="captchaAnswer">CAPTCHA · enter the code shown</label><div className="captcha-display"><span aria-label={`CAPTCHA code ${captcha}`}>{captcha || 'Loading...'}</span><button type="button" onClick={() => void refreshCaptcha()} aria-label="Generate a new CAPTCHA"><RefreshCw size={15} /></button></div></div><input id="captchaAnswer" value={captchaAnswer} onChange={event => setCaptchaAnswer(event.target.value)} autoComplete="off" maxLength={6} required aria-label="Enter CAPTCHA code" /></div>
        {error && <div className="form-message error-message" role="alert"><ShieldAlert size={16} />{error}</div>}
        <button className="primary-button full-width" disabled={busy || !captchaChallengeId}>{busy ? 'Please wait...' : 'Sign in'}<ArrowRight size={16} /></button>
      </form>
      <div className="auth-footnote"><LockKeyhole size={14} /> Demo authentication is handled by the local server.</div>
    </div>
  </section>;
}

function HomePage({ onChoose }: { onChoose: (domain: Domain) => void }) {
  return <>
    <section className="hero-panel"><div className="hero-content"><div className="hero-kicker"><Building2 size={15} /> FICTIONAL SERVICE PORTAL DEMO</div><h1>Everyday services,<br /><span>in one place.</span></h1><p>Explore sample customer services across eight fictional organizations. Choose a portal to sign in and browse its demo records.</p><button className="hero-button" onClick={() => document.getElementById('service-portals')?.scrollIntoView({ behavior: 'smooth' })}>Browse services <ArrowRight size={17} /></button></div>
      <div className="hero-art" aria-hidden="true"><div className="art-orbit orbit-one" /><div className="art-orbit orbit-two" /><div className="art-center"><Building2 size={43} /><span>SERVICE<br />DEMO</span></div><div className="art-node node-a"><Landmark /></div><div className="art-node node-b"><HeartPulse /></div><div className="art-node node-c"><GraduationCap /></div><div className="art-node node-d"><ShoppingBag /></div></div>
    </section>
    <section className="service-section" id="service-portals"><div className="section-title"><div><div className="eyebrow">SERVICE DIRECTORY</div><h2>Choose a service</h2><p>Each portal opens its own user sign-in and sample service workspace.</p></div><span className="count-pill">8 DEMO SERVICES</span></div>
      <div className="service-grid">{knownDomains.map((domain, index) => <button key={domain.id} className="service-card" onClick={() => onChoose(domain)}><span className="service-icon">{domainIcon(index)}</span><span className="service-copy"><b>{domain.name}</b><small>{domain.org}</small></span><span className="service-arrow"><ArrowRight size={17} /></span></button>)}</div>
    </section>
    <section className="safety-strip"><Shield size={20} /><div><b>Sample information for demonstration</b><p>Names, account references, balances, applications, and appointments shown after sign-in are fictional examples.</p></div></section>
  </>;
}

function ServiceDashboard({ user, domain, onLogout }: { user: User; domain: Domain; onLogout: () => void }) {
  const [record, setRecord] = useState<Customer | null>(null);
  const [profileLoading, setProfileLoading] = useState(true);
  const [accountNumber, setAccountNumber] = useState('');
  const [accessCode, setAccessCode] = useState('');
  const [bankError, setBankError] = useState('');
  const [balance, setBalance] = useState<{ balance: string; name: string; city: string; reference: string; kind: string; detail: string } | null>(null);
  const isBank = domain.id === 'banking';

  useEffect(() => {
    let mounted = true;
    api<Customer>('/api/profile').then(profile => { if (mounted) setRecord(profile); })
      .catch(() => { if (mounted) setRecord(null); })
      .finally(() => { if (mounted) setProfileLoading(false); });
    return () => { mounted = false; };
  }, [user.username]);

  const verifyBank = async (event: FormEvent) => {
    event.preventDefault(); setBankError(''); setBalance(null);
    try {
      const result = await api<{ balance: string; name: string; city: string; reference: string; kind: string; detail: string }>('/api/profile/bank-lookup', {
        method: 'POST', body: JSON.stringify({ account_number: accountNumber, access_code: accessCode }),
      });
      setBalance(result);
    } catch (issue) { setBankError((issue as Error).message); }
  };

  return <section className="customer-dashboard">
    <div className="page-heading"><div><div className="eyebrow">{domain.org.toUpperCase()}</div><h1>{isBank ? 'Banking overview' : `${domain.name} workspace`}</h1><p>Welcome, {user.display_name}. This sign-in can only access its assigned sample profile.</p></div><div className="heading-buttons"><button className="secondary-button" onClick={onLogout}><LogOut size={15} /> Sign out</button></div></div>
    <div className="sample-info-banner"><Shield size={17} /><span><b>Demonstration data only.</b> This is fictional sample information. Do not enter real personal, financial, or health details.</span></div>
    {profileLoading ? <div className="boot-status"><RefreshCw size={15} className="spin" /> Loading your sample profile...</div>
      : !record ? <div className="empty-state">No sample profile is assigned to this sign-in.</div>
      : isBank ? <>
        <section className="panel-card bank-lookup"><div className="panel-title"><span className="mini-icon"><Landmark size={19} /></span><div><h2>View your sample account</h2><p>Confirm your own demo account number and sample code to display your balance.</p></div></div>
          <div className="own-reference"><span>Your demo account number</span><b>{record.reference}</b><small>For this sample, your access code is the last four digits of the account number.</small></div>
          <form className="bank-lookup-form" onSubmit={verifyBank}><label>Demo account number<input value={accountNumber} onChange={event => setAccountNumber(event.target.value)} placeholder="Enter your demo account number" required autoComplete="off" /></label><label>Sample access code<input value={accessCode} onChange={event => setAccessCode(event.target.value)} placeholder="4-digit sample code" required inputMode="numeric" maxLength={4} autoComplete="off" /></label><button className="primary-button"><Landmark size={15} /> Show my sample balance</button></form>
          {bankError && <div className="form-message error-message" role="alert"><ShieldAlert size={16} />{bankError}</div>}
          {balance && <div className="bank-balance-card"><div><small>YOUR SAMPLE ACCOUNT BALANCE</small><strong>{balance.balance}</strong><span>{balance.kind} · {balance.city} demo branch</span></div><div><small>ACCOUNT HOLDER</small><b>{balance.name}</b><span>{balance.reference}</span></div><div><small>RECENT SAMPLE TRANSACTION</small><b>{balance.detail}</b><span>Example transaction only</span></div></div>}
        </section>
        <RecordSummary domain={domain} record={record} />
        <PrivateDocument />
      </> : <RecordSummary domain={domain} record={record} />}
    {!isBank && record && <PrivateDocument />}
    <div className="sample-footer-note">Only the profile assigned to this signed-in user is returned by the local service.</div>
  </section>;
}

function RecordSummary({ domain, record }: { domain: Domain; record: Customer }) {
  return <section className="record-detail panel-card"><div className="record-detail-heading"><div className="person-avatar"><UserRound size={23} /></div><div><div className="eyebrow">YOUR SAMPLE PROFILE</div><h2>{record.name}</h2><p>{domain.org} · {record.reference}</p></div><span className="person-status">{record.status}</span></div><div className="record-detail-grid"><div><small>{record.kindLabel.toUpperCase()}</small><b>{record.kind}</b></div>{record.detailLabel && <div><small>{record.detailLabel.toUpperCase()}</small><b>{record.detail}</b></div>}<div><small>{record.extraLabel.toUpperCase()}</small><b>{record.extra}</b></div><div><small>DEMO PROFILE STATUS</small><b>{record.status}</b></div></div></section>;
}

function PrivateDocument() {
  const [integrity, setIntegrity] = useState<{ filename: string; reference_sha256: string; current_sha256: string; status: string } | null>(null);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [fileCode, setFileCode] = useState('');
  const [downloadError, setDownloadError] = useState('');
  const [downloading, setDownloading] = useState(false);
  useEffect(() => { api<typeof integrity>('/api/profile/document/integrity').then(setIntegrity).catch(() => setIntegrity(null)); }, []);
  const downloadFile = async (event: FormEvent) => {
    event.preventDefault(); setDownloadError(''); setDownloading(true);
    try {
      const response = await fetch('/api/profile/document', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: fileCode }) });
      if (!response.ok) {
        let message = 'The file access code is incorrect.';
        try { const payload = await response.json(); if (typeof payload.detail === 'string') message = payload.detail; } catch { /* use the safe fallback */ }
        throw new Error(message);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = url; link.download = integrity?.filename || 'my-private-file.txt';
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
      setFileCode(''); setUnlockOpen(false);
    } catch (issue) { setDownloadError((issue as Error).message); }
    finally { setDownloading(false); }
  };
  return <section className="private-document panel-card"><div className="private-document-icon"><Shield size={20} /></div><div className="private-document-content"><div className="eyebrow">YOUR PRIVATE SAMPLE FILE</div><h2>{integrity?.filename || 'Loading your document...'}</h2><p>Only your signed-in account can download this file. SHA-256 integrity: <b className={integrity?.status === 'Verified' ? 'integrity-ok' : 'integrity-warn'}>{integrity?.status || 'Checking'}</b></p>{integrity && <details><summary>View SHA-256 hashes</summary><small>Reference: {integrity.reference_sha256}</small><small>Current: {integrity.current_sha256}</small></details>}</div><button className="secondary-button" type="button" onClick={() => { setUnlockOpen(true); setDownloadError(''); }}>Download my file <ArrowRight size={14} /></button>
    {unlockOpen && <div className="file-code-overlay"><section className="file-code-dialog" role="dialog" aria-modal="true" aria-labelledby="file-code-title"><button type="button" className="file-code-close" aria-label="Close" onClick={() => setUnlockOpen(false)}>×</button><div className="eyebrow">PRIVATE FILE ACCESS</div><h3 id="file-code-title">Enter your unique code</h3><p>This code is separate from your password and unlocks only your own sample file.</p><form onSubmit={downloadFile}><label htmlFor="file-access-code">File access code</label><input id="file-access-code" value={fileCode} onChange={event => setFileCode(event.target.value)} placeholder="Example: FILE-A7KQ-29" autoComplete="off" autoFocus required maxLength={32} /><button className="primary-button" disabled={downloading}>{downloading ? 'Verifying...' : 'Verify and download'} <ArrowRight size={15} /></button></form>{downloadError && <div className="form-message error-message" role="alert"><ShieldAlert size={16} />{downloadError}</div>}</section></div>}
  </section>;
}

function ChangePassword({ onComplete, onLogout }: { onComplete: () => void; onLogout: () => void }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('');
    if (password !== confirm) { setError('The two new passwords do not match.'); return; }
    setBusy(true);
    try {
      await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ new_password: password }) });
      onComplete();
    } catch (issue) { setError((issue as Error).message); }
    finally { setBusy(false); }
  };
  return <section className="auth-layout"><div className="auth-aside"><div className="domain-emblem"><LockKeyhole size={30} /></div><div className="eyebrow light-eyebrow">ACCOUNT ACTION REQUIRED</div><h1>Change your password</h1><p>A SENTINEL reviewer required a password change after unusual sign-in attempts. Set a new password to continue to your service account.</p></div><div className="auth-card"><div className="auth-card-heading"><div className="eyebrow">SECURE YOUR SAMPLE ACCOUNT</div><h2>Choose a new password</h2><p>Use at least 12 characters. This change applies only to your demo user account.</p></div><form className="auth-form" onSubmit={submit}><label>New password<input type="password" value={password} onChange={event => setPassword(event.target.value)} minLength={12} maxLength={256} autoComplete="new-password" required /></label><label>Confirm new password<input type="password" value={confirm} onChange={event => setConfirm(event.target.value)} minLength={12} maxLength={256} autoComplete="new-password" required /></label>{error && <div className="form-message error-message" role="alert"><ShieldAlert size={16} />{error}</div>}<button className="primary-button full-width" disabled={busy}>{busy ? 'Updating...' : 'Change password now'}<ArrowRight size={16} /></button></form><div className="auth-options"><button onClick={onLogout}>Sign out instead</button></div></div></section>;
}
export default function App() {
  const [page, setPage] = useState<Page>('home');
  const [selectedDomain, setSelectedDomain] = useState<Domain | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');

  useEffect(() => {
    let mounted = true;
    api<User>('/api/auth/me').then(sessionUser => {
      if (mounted) { setUser(sessionUser); setSelectedDomain(knownDomains.find(domain => domain.id === sessionUser.domain) || null); setPage(sessionUser.must_change_password ? 'change-password' : 'dashboard'); }
    }).catch(() => undefined).finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (!user || page !== 'dashboard') return;
    const timer = window.setInterval(() => {
      api<User>('/api/auth/me').then(current => {
        if (current.must_change_password) { setUser(current); setPage('change-password'); }
      }).catch(() => { setUser(null); setPage('login'); setNotice('Your session was ended. Sign in again to continue.'); });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [user?.username, page]);

  const navigate = (next: Page) => { setNotice(''); setPage(next); window.scrollTo({ top: 0, behavior: 'smooth' }); };
  const openPortal = (domain: Domain) => { setSelectedDomain(domain); setPage('login'); setNotice(''); window.scrollTo({ top: 0, behavior: 'smooth' }); };
  const logout = async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* Local sign-out below still clears this screen. */ }
    setUser(null); setSelectedDomain(null); setPage('home'); setNotice('You have signed out.');
  };
  const onAuthenticated = (signedInUser: User) => {
    setUser(signedInUser); setSelectedDomain(knownDomains.find(domain => domain.id === signedInUser.domain) || null);
    setPage(signedInUser.must_change_password ? 'change-password' : 'dashboard'); setNotice('');
  };
  const passwordChanged = () => { setUser(current => current ? { ...current, must_change_password: false } : current); setPage('dashboard'); };
  const domain = knownDomains.find(item => item.id === user?.domain) || selectedDomain;

  return <div className="site-shell">
    <Header page={page} user={user} onNavigate={navigate} onLogout={logout} />
    <main className="content-shell">
      {notice && <div className="notice-bar notice-info" role="status">{notice}</div>}
      {page === 'home' && <HomePage onChoose={openPortal} />}
      {page === 'login' && selectedDomain && <PortalAuth domain={selectedDomain} onBack={() => navigate('home')} onAuthenticated={onAuthenticated} />}
      {page === 'change-password' && user && <ChangePassword onComplete={passwordChanged} onLogout={logout} />}
      {page === 'dashboard' && user && domain && <ServiceDashboard key={user.domain} user={user} domain={domain} onLogout={logout} />}
      {loading && <div className="boot-status"><RefreshCw size={15} className="spin" /> Connecting to the local demonstration...</div>}
    </main>
    <footer className="portal-footer"><span><Building2 size={15} /> CivicShield service demonstration</span><span>Fictional sample records · No government affiliation</span><span>Do not enter real personal or financial details.</span></footer>
  </div>;
}
