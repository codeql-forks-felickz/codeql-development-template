import React from "react";
import { useQuery } from "@tanstack/react-query";

async function fetchBio(username: string): Promise<string> {
  const res = await fetch(`/api/user/${username}/bio`); // $ Source[js/xss]
  if (!res.ok) {
    throw new Error("Failed to fetch user bio");
  }
  return res.json();
}

export function useBio(username: string) {
  return useQuery({
    queryKey: ["bio", username],
    queryFn: () => fetchBio(username),
  });
}

// Stored XSS: the profile bio returned by the API is rendered as raw HTML.
export function ProfileHeader({ username }: { username: string }) {
  const { data: bio } = useBio(username);
  return (
    <div>
      <p>{bio}</p>
      <div dangerouslySetInnerHTML={{ __html: bio ? bio : "" }} /> {/* $ Alert[js/xss] */}
    </div>
  );
}
