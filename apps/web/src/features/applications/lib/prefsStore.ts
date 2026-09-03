/**
 * Applications-surface UI preferences (zustand + persist), feature-scoped.
 *
 * Holds ONLY presentation state owned by the Applications home / App overview
 * surfaces:
 * - pinned application order (the pin *flag* itself is domain data and lives
 *   in the client boundary via `applications.setPinned`; this is the user's
 *   manual ordering of pinned rows),
 * - the All-applications sort preference,
 * - first-run onboarding strip dismissal,
 * - optimistic overlays for package state the client boundary cannot mutate
 *   yet (checklist item toggles, study goal edits). These overlays are
 *   deliberately keyed `${instanceId}:${itemId}` so a future client contract
 *   (`applications.toggleChecklistItem` / `applications.updateStudyGoal`)
 *   can replace them without migration — tracked as a contract gap.
 * - bounded StudyState reflection drafts. These are browser-local convenience
 *   data, never canonical learning state or assessed evidence.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const APPLICATIONS_PREFS_STORAGE_KEY = 'stateport.applications.v1'

export type ApplicationsSort = 'recent' | 'name' | 'package'

interface ApplicationsPrefsState {
  /** Pinned instance ids in user order (ascending = first). */
  pinnedOrder: string[]
  sort: ApplicationsSort
  onboardingDismissed: boolean
  /** Optimistic checklist toggles: `${instanceId}:${itemId}` → done. */
  checklistDoneOverrides: Record<string, boolean>
  /** Optimistic study goal edits: instanceId → goal sentence. */
  studyGoalOverrides: Record<string, string>
  /** Browser-local reflection drafts: `${instanceId}:${activityId}` → text. */
  studyReflectionDrafts: Record<string, string>

  setPinnedOrder(order: string[]): void
  /** Move a pinned id from one index to another (keyboard/drag reorder). */
  movePinned(id: string, toIndex: number): void
  /** Ensure the order list matches the currently pinned set (append new, drop unpinned). */
  reconcilePinned(pinnedIds: string[]): string[]
  setSort(sort: ApplicationsSort): void
  dismissOnboarding(): void
  setChecklistDone(instanceId: string, itemId: string, done: boolean): void
  setStudyGoal(instanceId: string, goal: string): void
  setStudyReflectionDraft(instanceId: string, activityId: string, reflection: string): void
  clearStudyReflectionDraft(instanceId: string, activityId: string): void
  /** Drop all browser-local checklist overrides for one instance. */
  resetChecklist(instanceId: string): void
  /** Drop the browser-local study goal draft for one instance. */
  resetStudyGoal(instanceId: string): void
}

export const useApplicationsPrefs = create<ApplicationsPrefsState>()(
  persist(
    (set, get) => ({
      pinnedOrder: [],
      sort: 'recent',
      onboardingDismissed: false,
      checklistDoneOverrides: {},
      studyGoalOverrides: {},
      studyReflectionDrafts: {},

      setPinnedOrder: (pinnedOrder) => set({ pinnedOrder }),
      movePinned: (id, toIndex) =>
        set((s) => {
          const from = s.pinnedOrder.indexOf(id)
          if (from === -1) return s
          const next = [...s.pinnedOrder]
          next.splice(from, 1)
          next.splice(Math.max(0, Math.min(toIndex, next.length)), 0, id)
          return { pinnedOrder: next }
        }),
      reconcilePinned: (pinnedIds) => {
        const current = get().pinnedOrder
        const kept = current.filter((id) => pinnedIds.includes(id))
        const missing = pinnedIds.filter((id) => !kept.includes(id))
        const next = [...kept, ...missing]
        if (next.length !== current.length || next.some((id, i) => id !== current[i])) {
          set({ pinnedOrder: next })
        }
        return next
      },
      setSort: (sort) => set({ sort }),
      dismissOnboarding: () => set({ onboardingDismissed: true }),
      setChecklistDone: (instanceId, itemId, done) =>
        set((s) => ({
          checklistDoneOverrides: { ...s.checklistDoneOverrides, [`${instanceId}:${itemId}`]: done },
        })),
      setStudyGoal: (instanceId, goal) =>
        set((s) => ({ studyGoalOverrides: { ...s.studyGoalOverrides, [instanceId]: goal } })),
      setStudyReflectionDraft: (instanceId, activityId, reflection) =>
        set((s) => ({
          studyReflectionDrafts: {
            ...s.studyReflectionDrafts,
            [`${instanceId}:${activityId}`]: reflection.slice(0, 280),
          },
        })),
      clearStudyReflectionDraft: (instanceId, activityId) =>
        set((s) => {
          const next = { ...s.studyReflectionDrafts }
          delete next[`${instanceId}:${activityId}`]
          return { studyReflectionDrafts: next }
        }),
      resetChecklist: (instanceId) =>
        set((s) => ({
          checklistDoneOverrides: Object.fromEntries(
            Object.entries(s.checklistDoneOverrides).filter(([key]) => !key.startsWith(`${instanceId}:`)),
          ),
        })),
      resetStudyGoal: (instanceId) =>
        set((s) => ({
          studyGoalOverrides: Object.fromEntries(
            Object.entries(s.studyGoalOverrides).filter(([key]) => key !== instanceId),
          ),
        })),
    }),
    {
      name: APPLICATIONS_PREFS_STORAGE_KEY,
      version: 1,
    },
  ),
)
