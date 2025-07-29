import express from 'express';
import { login, logout, handleRedirect } from '../session-auth.js';
import {
  Session,
  EVENTS
} from "@inrupt/solid-client-authn-node"

const router = express.Router();

router.get('/login', (req, res) => res.render('login', { title: 'Login', sendTo: req.query.sendTo }));
router.post('/login', login);
router.get("/redirect", handleRedirect);

router.get('/logout', logout);



export default router;
