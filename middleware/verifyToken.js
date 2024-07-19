import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    console.log('Received token:', token);
    if (!token) {
        console.log('No token provided');
        return res.status(401).json({ message: 'No token provided' });
    }

    const secretKey = process.env.TOKEN_ACCESS_SECRET;
    console.log('Secret key:', secretKey); // Log the secret key (be cautious with this in production)

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            return res.status(403).json({
                message: 'Failed to authenticate token',
                error: err.message
            });
        }
        console.log('Token verified successfully. Decoded:', decoded);
        req.userId = decoded.id;
        next();
    });
};

export default verifyToken;
