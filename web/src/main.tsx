import '@fontsource-variable/archivo/wdth.css';
import '@fontsource/courier-prime/400.css';
import './design/tokens.css';
import './design/base.css';
import { lazy, StrictMode, Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router';
import Landing from './landing/Landing';
import { Seal } from './Seal';
import { applyStoredTheme } from './ThemeToggle';

// The landing ships in the first bundle (no blank first paint); the console and three.js load on demand.
const Console = lazy(() => import('./console/Console'));

applyStoredTheme();

/** While the console's code downloads (about a second on a cold visit). */
function Boot() {
  return (
    <div className="boot" role="status">
      <Seal size={44} />
      <span>Opening the console…</span>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Suspense fallback={<Boot />}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/console/*" element={<Console />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  </StrictMode>,
);
