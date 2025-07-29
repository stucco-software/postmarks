import session from 'express-session';
import { dataDir } from './util.js';
import {
  Session,
  EVENTS
} from "@inrupt/solid-client-authn-node"

const CLIENT_ID = "https://stucco.software/applications/postmarks.json"
const REDIRECT_URL = "http://localhost:3000/redirect"
const OPENID_PROVIDER = "https://login.stucco.software/"

// For simplicity, the cache is here an in-memory map. In a real application,
// tokens and auth state would be stored in a persistent storage.
export const sessionCache = {};
export const updateSessionCache = (sessionId, data) => {
  sessionCache[sessionId] = data;
};

export default () =>
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 },
  });

export function isAuthenticated(req, res, next) {
  console.log(req.session.sessionId)
  const authorizationRequestState = sessionCache[req.session.sessionId];
  console.log(req.session.sessionId, req.session.isLoggedIn, authorizationRequestState)
  if (authorizationRequestState && authorizationRequestState.accessToken) next();
  else res.redirect(`/login?sendTo=${encodeURIComponent(req.originalUrl)}`);
}

export async function login(req, res, next) {
  req.session.regenerate(async (err) => {
    if (err) {
      next(err);
    }
    const session = new Session({ keepAlive: false })
    req.session.sessionId = session.info.sessionId
    session.events.on(EVENTS.AUTHORIZATION_REQUEST, (authorizationRequestState) => {
      updateSessionCache(session.info.sessionId, authorizationRequestState);
    })
    await session.login({
      clientId: CLIENT_ID,
      redirectUrl: REDIRECT_URL,
      oidcIssuer: OPENID_PROVIDER,
      handleRedirect: (redirectUrl) => res.redirect(redirectUrl),
    })
  })
}

export async function handleRedirect(req, res) {
  const authorizationRequestState = sessionCache[req.session.sessionId];
  if (authorizationRequestState === undefined) {
    res
        .status(401)
        .send(`<p>No authorizationRequestState stored for ID [${req.session.sessionId}]</p>`);
    return;
  }

  const session = await Session.fromAuthorizationRequestState(authorizationRequestState, req.session.sessionId);
  if (session === undefined) {
    res
      .status(400)
      .send(`<p>No session stored for ID [${req.session.sessionId}]</p>`);
    return;
  }

  session.events.on(
    EVENTS.NEW_TOKENS,
    (tokenSet) => updateSessionCache(req.session.sessionId, tokenSet)
  );

  await session.handleIncomingRedirect(getRequestFullUrl(req))

  console.log(`session logged in?`)
  console.log(session.info)

  if (session.info.isLoggedIn) {
    req.session.loggedIn = true;
    // console.log(req.session)
    // req.session.save((err) => {
    //   console.log('save?')
    //   if (err) {
    //     next(err);
    //   }
    //   req.session.regenerate((regenErr) => {
    //     console.log(`regenerate?`)
    //     if (regenErr) {
    //       next(regenErr);
    //     }
    //     res.redirect('/admin')
    //   });
    // });
    res.redirect('/admin')
  } else {
    res.status(400).send(`<p>Not logged in after redirect</p>`);
  }
  // res.end();
}

export function logout(req, res, next) {
  req.session.user = null;
  req.session.save((err) => {
    if (err) {
      next(err);
    }
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        next(regenErr);
      }
      res.redirect('/');
    });
  });
}

// @TKTK this probably a util
function getRequestFullUrl(request) {
  return `${request.protocol}://${request.get("host")}${request.originalUrl}`;
}