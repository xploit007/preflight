export default function Comment({ comment }) {
  return (
    <article className="comment">
      <h3>{comment.author}</h3>
      <div dangerouslySetInnerHTML={{ __html: comment.body }} />
    </article>
  );
}
