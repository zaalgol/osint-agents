import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./styles.css";
import { ToastProvider } from "./components/ui";
import { Shell } from "./components/Shell";
import { Dashboard } from "./pages/Dashboard";
import { NewInvestigation } from "./pages/NewInvestigation";
import { InvestigationPage } from "./pages/Investigation";
import { EntityPage } from "./pages/EntityPage";
import { DocumentPage } from "./pages/DocumentPage";
import { SearchPage } from "./pages/SearchPage";
import { ReviewPage } from "./pages/ReviewPage";
import { SourcesPage } from "./pages/SourcesPage";
import { JobsPage, JobPage } from "./pages/JobsPage";
import { SystemPage } from "./pages/SystemPage";

const qc = new QueryClient({
  defaultOptions: { queries: { staleTime: 10_000, refetchOnWindowFocus: false, retry: 1 } },
});

try {
  const theme = localStorage.getItem("theme");
  if (theme) document.documentElement.dataset.theme = theme;
} catch { /* storage unavailable */ }

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <ToastProvider>
          <Routes>
            <Route element={<Shell />}>
              <Route index element={<Dashboard />} />
              <Route path="new" element={<NewInvestigation />} />
              <Route path="inv/:id" element={<InvestigationPage />} />
              <Route path="inv/:id/:tab" element={<InvestigationPage />} />
              <Route path="entity/:id" element={<EntityPage />} />
              <Route path="doc/:id" element={<DocumentPage />} />
              <Route path="search" element={<SearchPage />} />
              <Route path="review" element={<ReviewPage />} />
              <Route path="sources" element={<SourcesPage />} />
              <Route path="jobs" element={<JobsPage />} />
              <Route path="jobs/:id" element={<JobPage />} />
              <Route path="system" element={<SystemPage />} />
              <Route path="*" element={<div className="page"><h1>Not found</h1></div>} />
            </Route>
          </Routes>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
