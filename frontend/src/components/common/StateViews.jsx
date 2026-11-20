export function LoadingState({ label = "Loading" }) {
  return <p role="status">{label}…</p>;
}

export function ErrorState({ message = "Something went wrong." }) {
  return <p role="alert">{message}</p>;
}

export function EmptyState({ message = "No data available." }) {
  return <p>{message}</p>;
}
