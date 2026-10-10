import { ReviewList } from "../tabs/ReviewList";

export function ReviewPage() {
  return (
    <div className="page">
      <h1>Review queue</h1>
      <div className="muted" style={{ marginBottom: 14 }}>
        Things the system won't decide alone: sanctions matches on people, merges, contradictions, Claude's proposed revisions, image metadata. Every decision is recorded with who and when.
      </div>
      <ReviewList />
    </div>
  );
}
