export default function Comment({ comment }) {
  return (
    <article className="comment">
      <h2>{comment.title}</h2>
      <p>{comment.body}</p>
    </article>
  );
}
