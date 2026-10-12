import { useEffect, useState } from 'react';
import { supabase } from './lib/supabase.js';
import Comment from './components/Comment.jsx';

export default function App() {
  const [notes, setNotes] = useState([]);
  const [draft, setDraft] = useState('');

  useEffect(() => {
    supabase.from('notes').select('id, title, body').then(({ data }) => setNotes(data || []));
  }, []);

  return (
    <main className="app">
      <header>
        <a href="/" aria-label="ShipNotes home">
          <img src="/logo.png" alt="ShipNotes" width="32" height="32" />
        </a>
        <h1>Your notes</h1>
        <button type="button" aria-label="Print notes" onClick={() => window.print()}>
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16"><path d="M2 2h12v12H2z" /></svg>
        </button>
      </header>
      <form role="search" onSubmit={(e) => e.preventDefault()}>
        <label htmlFor="draft">New note</label>
        <input id="draft" value={draft} onChange={(e) => setDraft(e.target.value)} />
        <button type="submit">Save</button>
      </form>
      <section aria-label="Notes">
        {notes.map((n) => (
          <Comment key={n.id} comment={n} />
        ))}
      </section>
    </main>
  );
}
