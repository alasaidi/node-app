import express from 'express';
import userControllers from '../controllers/user.js';

const router = express.Router();
const { register, login, logout } = userControllers;

// routes

router.post('/', login);
router.post('/register', register);
router.get('/logout', logout);

export default router;
