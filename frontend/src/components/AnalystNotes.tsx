import { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { createAnnotation, deleteAnnotation, errorMessage, getAnnotations, updateAnnotation } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { fmtUtc } from '../lib/format';
import type { AnnotationTarget } from '../types/api';

/**
 * Analyst notes and "include in investigation report" selection for one item.
 * Stored server-side with the analysis. Analyst metadata only: evidence, findings, severity and
 * the score are never changed. Selected items appear in an appendix of generated reports.
 */
export const AnalystNotes = ({ captureId, targetType, targetId }: {
  captureId: string; targetType: AnnotationTarget; targetId: string;
}) => {
  const notes = useAsync(() => getAnnotations(captureId, targetType, targetId), `${captureId}|${targetType}|${targetId}`);
  const [text, setText] = useState('');
  const [include, setInclude] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const selected = (notes.data ?? []).some((n) => n.include_in_report);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      notes.reload();
    } catch (e) {
      setErr(errorMessage(e, 'Could not save the note'));
    } finally {
      setBusy(false);
    }
  };
  const add = () => run(async () => {
    await createAnnotation(captureId, { target_type: targetType, target_id: targetId, text, include_in_report: include });
    setText('');
    setInclude(false);
  });
  const fieldId = `note-${targetType}`;

  return (
    <section aria-labelledby={`${fieldId}-h`} className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id={`${fieldId}-h`} className="text-sm font-semibold">Analyst notes</h3>
        {selected && <span className="text-xs border border-signal text-signal rounded-sm px-1.5 py-px">In investigation report</span>}
      </div>
      {notes.error && <p role="alert" className="text-sm text-sev-high">{notes.error}</p>}
      {(notes.data ?? []).length > 0 && (
        <ul className="space-y-1.5">
          {notes.data!.map((n) => (
            <li key={n.id} className="border border-line rounded px-2.5 py-2 text-sm bg-sunken">
              {n.text ? <p className="whitespace-pre-wrap break-words">{n.text}</p> : <p className="text-ink-3">Selected for the report (no note)</p>}
              <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-3">
                <span>{fmtUtc(n.created_at)}</span>
                <label className="inline-flex items-center gap-1.5">
                  <input type="checkbox" checked={n.include_in_report} disabled={busy}
                    onChange={(e) => void run(() => updateAnnotation(n.id, { include_in_report: e.target.checked }))} />
                  Include in investigation report
                </label>
                <button type="button" className="inline-flex items-center gap-1 hover:text-sev-high" disabled={busy}
                  onClick={() => void run(() => deleteAnnotation(n.id))}><Trash2 size={12} aria-hidden="true" />Delete</button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <label htmlFor={fieldId} className="sr-only">New note</label>
      <textarea id={fieldId} value={text} onChange={(e) => setText(e.target.value)} maxLength={4000} rows={2}
        placeholder="Add a note (context, owner, decision)" className="field w-full resize-y" />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="inline-flex items-center gap-1.5 text-xs text-ink-2">
          <input type="checkbox" checked={include} onChange={(e) => setInclude(e.target.checked)} />
          Include this item in the investigation report
        </label>
        <button type="button" className="btn" disabled={busy || (!text.trim() && !include)} onClick={() => void add()}>
          {text.trim() ? 'Add note' : 'Select for report'}
        </button>
      </div>
      {err && <p role="alert" className="text-sm text-sev-high">{err}</p>}
      <p className="text-xs text-ink-3">Notes are analyst metadata. They do not change evidence, findings or the score.</p>
    </section>
  );
};
