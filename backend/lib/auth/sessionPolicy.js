'use strict';

const { SESSION_IDLE_MINUTES, SESSION_MAX_HOURS } = require('../config');

const IDLE_MS = SESSION_IDLE_MINUTES * 60_000;
const MAX_MS = SESSION_MAX_HOURS * 3_600_000;
// Recording every request would write the session store on every call; a
// minute of slack on the idle clock is not worth that.
const ACTIVITY_GRANULARITY_MS = 60_000;

function startSession(session, now = Date.now()) {
  session.authenticatedAt = now;
  session.lastSeenAt = now;
}

// A browser session ends after IDLE without a request or MAX after sign-in,
// whichever comes first. Sessions created before these timestamps existed
// carry neither and must sign in again.
function sessionExpired(session, now = Date.now()) {
  const { authenticatedAt, lastSeenAt } = session || {};
  if (!Number.isFinite(authenticatedAt) || !Number.isFinite(lastSeenAt)) return true;
  return now - authenticatedAt >= MAX_MS || now - lastSeenAt >= IDLE_MS;
}

function noteActivity(session, now = Date.now()) {
  if (now - session.lastSeenAt >= ACTIVITY_GRANULARITY_MS) session.lastSeenAt = now;
}

module.exports = { IDLE_MS, MAX_MS, startSession, sessionExpired, noteActivity };
