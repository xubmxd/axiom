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
  // ---- Cyber Range ----
  labProvider: process.env.LAB_PROVIDER || "auto", // docker | local | auto
  labDockerSubnetBase: process.env.LAB_DOCKER_SUBNET_BASE || "10.210",
  labLocalSubnetBase: process.env.LAB_LOCAL_SUBNET_BASE || "10.200",
  axiomSelfContainer: process.env.AXIOM_SELF_CONTAINER || "",
  // ---- Student VPN (WireGuard gateway so personal Kali VMs reach lab targets) ----
  vpnEnabled: (process.env.VPN_ENABLED || "0") === "1",
  vpnSubnetBase: process.env.VPN_SUBNET_BASE || "10.212", // /24 for student tunnel IPs; keep clear of lab bases
  vpnEndpointHost: process.env.VPN_ENDPOINT_HOST || "", // LAN/public IP or hostname students connect to
  vpnEndpointPort: parseInt(process.env.VPN_ENDPOINT_PORT || "51820", 10),
  vpnGatewayContainer: process.env.VPN_GATEWAY_CONTAINER || "axiom-vpn",
};
