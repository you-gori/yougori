import profile from "../../distribution.txt?raw"

/** Compiled into the app. Public exports cannot enable this through preferences or environment variables. */
export const LIVE_TARGETS = profile === "private\n" || profile === "private\r\n"
