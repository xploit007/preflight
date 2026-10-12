import { useEffect, useState } from 'react';
import { supabase } from './lib/supabase';
import Comment from './components/Comment.jsx';
import Checkout from './components/Checkout.jsx';

export default function App() {
  const [notes, setNotes] = useState([]);

  useEffect(() => {
    supabase.from('notes').select('*').then(({ data }) => setNotes(data || []));
    localStorage.setItem('token', new URLSearchParams(window.location.search).get('token'));
  }, []);

  return (
    <div className="app">
      <div className="logo" onClick={() => (window.location.href = '/')}>
        <img src="/logo.png" />
      </div>
      <button onClick={() => window.print()}>
        <svg width="16" height="16" viewBox="0 0 16 16"><path d="M2 2h12v12H2z" /></svg>
      </button>
      {notes.map((n) => (
        <Comment key={n.id} comment={n} />
      ))}
      <Checkout />
    </div>
  );
}
