import { create } from 'zustand';
import type { AnalysisListItem, AnalysisResult } from './api';
import { listAnalyses, getAnalysis, uploadFile, deleteAnalysis } from './api';

interface ShadowBoxStore {
  // Analyses list
  analyses: AnalysisListItem[];
  loading: boolean;
  error: string | null;
  fetchAnalyses: () => Promise<void>;

  // Current analysis
  currentAnalysis: AnalysisResult | null;
  currentLoading: boolean;
  fetchAnalysis: (id: string) => Promise<void>;
  pollAnalysis: (id: string) => void;
  stopPolling: () => void;

  // Upload
  uploading: boolean;
  uploadError: string | null;
  upload: (file: File) => Promise<string>;

  // Delete
  removeAnalysis: (id: string) => Promise<void>;
}

let pollInterval: ReturnType<typeof setInterval> | null = null;

export const useStore = create<ShadowBoxStore>((set, get) => ({
  analyses: [],
  loading: false,
  error: null,

  fetchAnalyses: async () => {
    set({ loading: true, error: null });
    try {
      const analyses = await listAnalyses();
      set({ analyses, loading: false });
    } catch (e: unknown) {
      set({ error: (e as Error).message, loading: false });
    }
  },

  currentAnalysis: null,
  currentLoading: false,

  fetchAnalysis: async (id: string) => {
    set({ currentLoading: true });
    try {
      const analysis = await getAnalysis(id);
      set({ currentAnalysis: analysis, currentLoading: false });
    } catch {
      set({ currentLoading: false });
    }
  },

  pollAnalysis: (id: string) => {
    get().stopPolling();
    // Fetch immediately
    get().fetchAnalysis(id);
    // Then poll every 2 seconds
    pollInterval = setInterval(async () => {
      try {
        const analysis = await getAnalysis(id);
        set({ currentAnalysis: analysis });
        if (analysis.status === 'completed' || analysis.status === 'error') {
          get().stopPolling();
        }
      } catch {
        // Ignore poll errors
      }
    }, 2000);
  },

  stopPolling: () => {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  },

  uploading: false,
  uploadError: null,

  upload: async (file: File) => {
    set({ uploading: true, uploadError: null });
    try {
      const result = await uploadFile(file);
      set({ uploading: false });
      // Refresh list
      get().fetchAnalyses();
      return result.analysis_id;
    } catch (e: unknown) {
      set({ uploading: false, uploadError: (e as Error).message });
      throw e;
    }
  },

  removeAnalysis: async (id: string) => {
    await deleteAnalysis(id);
    set((state) => ({
      analyses: state.analyses.filter((a) => a.id !== id),
    }));
  },
}));
