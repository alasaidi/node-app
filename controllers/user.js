import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import validateEmail from '../utils/validateEmail.js';
import validatePassword from '../utils/validatePassword.js';
import matchPasswords from '../utils/matchPasswords.js';
import hashPassword from '../utils/hashPassword.js';
import query from '../config/db.js';

const userControllers = {
    register: async (req, res) => {
        try {
            const { username, email, password } = req.body;

            // Validate input
            if (!username || !email || !password) {
                return res
                    .status(400)
                    .json({ message: 'All fields are required' });
            }

            if (!validateEmail(email)) {
                return res
                    .status(400)
                    .json({ message: 'Invalid email format' });
            }

            if (!validatePassword(password)) {
                return res
                    .status(400)
                    .json({ message: 'Password does not meet requirements' });
            }

            // Check if user already exists
            const existingUser = await query(
                'SELECT * FROM users WHERE email = ?',
                [email]
            );
            if (existingUser.length > 0) {
                return res.status(409).json({ message: 'User already exists' });
            }

            // Hash password
            const hashedPassword = await hashPassword(password);
            // console.log('Hashed password:', hashedPassword);

            // Insert new user
            const result = await query(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword]
            );

            res.status(201).json({
                message: 'User registered successfully',
                userId: result.insertId
            });
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    },

    login: async (req, res) => {
        try {
            const { email, password } = req.body;

            // Validate input
            if (!email || !password) {
                return res
                    .status(400)
                    .json({ message: 'Email and password are required' });
            }

            // Find user
            const users = await query('SELECT * FROM users WHERE email = ?', [
                email
            ]);

            if (users.length === 0) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const user = users[0];

            // console.log('Input password:', password);
            // console.log('Stored password hash:', user.password);
            // console.log('Password type:', typeof password);
            // console.log('Stored hash type:', typeof user.password);

            // Check password

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Generate JWT
            const token = jwt.sign(
                { id: user.id },
                process.env.TOKEN_ACCESS_SECRET,
                { expiresIn: '1h' }
            );

            // Set cookie
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 3600000 // 1 hour
            });

            res.json({ message: 'Login successful', userId: user.id });
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    },

    logout: async (req, res) => {
        try {
            // Clear the token cookie
            res.clearCookie('token');
            res.json({ message: 'Logout successful' });
        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
};

export default userControllers;
