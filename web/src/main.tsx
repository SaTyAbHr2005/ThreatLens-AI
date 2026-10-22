import '@fontsource-variable/archivo/wdth.css';
import '@fontsource/courier-prime/400.css';
import './design/tokens.css';
import './design/base.css';
import { lazy, StrictMode, Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router';
import Landing from './landing/Landing';
import { applyStoredTheme } from './ThemeToggle';

// The landing ships in the first bundle (no blank first paint); the console and three.js load on demand.
const Console = lazy(() => import('./console/Console'));

applyStoredTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/console/*" element={<Console />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  </StrictMode>,
);
