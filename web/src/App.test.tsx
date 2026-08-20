import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import App from './App';

describe('dashboard preview', () => {
  it('renders the alpha disclosure without implying a live security boundary', () => {
    const markup = renderToStaticMarkup(<App />);

    expect(markup).toContain('0.10.0-alpha.1 static preview');
    expect(markup).toContain('not connected to the Rust API');
    expect(markup).toContain('No authentication');
    expect(markup).toContain('Not connected');
  });
});
