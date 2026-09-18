import path from "node:path";

export const config = {
  port: parseInt(process.env.PORT || "3100", 10),
  appUrl: process.env.APP_URL || "http://localhost:3100",
  coursesRoot: process.env.COURSES_ROOT || path.resolve("courses"),
  dataDir: process.env.DATA_DIR || path.resolve("data"),
  databaseUrl: process.env.DATABASE_URL || "",
  sessionSecret: process.env.SESSION_SECRET || "dev-only-change-me",
  sessionDays: parseInt(process.env.SESSION_DAYS || "30", 10),
  videoCompletionThreshold: parseFloat(process.env.VIDEO_COMPLETION_THRESHOLD || "0.9"),
  readingCompletionThreshold: parseFloat(process.env.READING_COMPLETION_THRESHOLD || "0.9"),
  readingInactivitySecs: parseInt(process.env.READING_INACTIVITY_TIMEOUT || "60", 10),
  heartbeatSecs: parseInt(process.env.LEARNING_SESSION_HEARTBEAT || "15", 10),
  streakMinutes: parseInt(process.env.STREAK_MINUTES || "15", 10),
  appVersion: "1.0.0",
};
