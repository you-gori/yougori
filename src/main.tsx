// Keep this entry dependency-free so the HTML loading screen can paint while
// React, the graph, styles and native platform state are being prepared.
// Move browser preferences before any UI module reads them. Keep a newer
// Yougori value if both generations exist.
import { PREFERENCE_PREFIX } from "./lib/legacy-names"

try {
  for (let index = localStorage.length - 1; index >= 0; index--) {
    const previous = localStorage.key(index)
    if (!previous?.startsWith(PREFERENCE_PREFIX)) continue
    const current = `yougori.${previous.slice(PREFERENCE_PREFIX.length)}`
    if (localStorage.getItem(current) === null) {
      const value = localStorage.getItem(previous)
      if (value !== null) localStorage.setItem(current, value)
    }
    localStorage.removeItem(previous)
  }
  // The in-app CLI and Edit the App are gone: drop their saved view and remembered source folder.
  for (const key of ["yougori.workspace-view", "yougori.edit-source-checkout"]) localStorage.removeItem(key)
} catch (error) {
  console.warn("Yougori could not migrate browser preferences", error)
}
void import("./bootstrap").catch(error => {
  console.error("Yougori frontend startup failed", error)
  const message = document.querySelector(".startup-message")
  if (message) {
    message.textContent = "Yougori couldn’t load. Please close and reopen the app."
    message.setAttribute("role", "alert")
  }
  document.querySelector(".startup-screen")?.setAttribute("aria-busy", "false")
  document.querySelector(".startup-track")?.remove()
})
