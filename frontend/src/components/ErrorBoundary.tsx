import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

/** Keeps a rendering failure in one view from blanking the whole workstation. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('View failed to render', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div role="alert" className="panel panel-body space-y-2">
          <h1 className="text-xl">This view could not be displayed</h1>
          <p className="text-sm text-ink-2">The analysis data is unaffected. Reload the page, or go back to the overview.</p>
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={() => window.location.reload()}>Reload</button>
            <a href="/" className="btn-primary">Overview</a>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
