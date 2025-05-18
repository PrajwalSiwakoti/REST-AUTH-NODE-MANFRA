const express = require('express');
const DataStore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

const config = require('./config.js');

const app = express();

//configure body parser
app.use(express.json());

const cache = new NodeCache({ stdTTL: 100, checkperiod: 120 });

//simulating a database with nedb
//nedb is a lightweight database for Node.js, it stores data in JSON format and is easy to use
const users = DataStore.create({ filename: 'users.db', autoload: true });

const userRefreshTokens = DataStore.create({ filename: 'userRefreshTokens.db', autoload: true });

const userInvalidTokens = DataStore.create({ filename: 'userInvalidTokens.db', autoload: true });

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/api/auth/register', async (req, res) => {

    try {
        const { name, email, password, role } = req.body;

        if(!name || !email || !password) {
            return res.status(422).json({ message: 'Please fill all fields' });
        }

        const userExists = await users.findOne({ email });
        if(userExists) {
            return res.status(422).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await users.insert({ 
            name, 
            email, 
            password: hashedPassword,
            role: role || 'member', // default role is member
            '2faEnabled': false,
            '2faSecret': null
        });

        return res.status(201).json({ 
            message: 'User created successfully', 
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            } 
        });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
  
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if(!email || !password) {
            return res.status(422).json({ message: 'Please fill all fields' });
        }

        const user = await users.findOne({ email });
        if(!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check if 2FA is enabled
        if(user['2faEnabled']) {
            // If 2FA is enabled, we need to generate token
            const tempToken = crypto.randomUUID();
           
            cache.set(config.cacheTemporaryTokenPrefx + tempToken, user._id, config.cacheTemporaryTokenExpiration);

            return res.status(200).json({
                message: '2FA is enabled, please verify your OTP',
                tempToken,
                expirationTimeInSeconds: config.cacheTemporaryTokenExpiration,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email
                }
            });
        }

        const accessToken = jwt.sign({ id: user._id, email: user.email }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiration });
        const refreshToken = jwt.sign({ id: user._id, email: user.email }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });

        // Store the refresh token in the database
        await userRefreshTokens.insert({ token: refreshToken, userId: user._id });

        return res.status(200).json({ 
            message: 'User logged in successfully', 
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken: accessToken,
                refreshToken: refreshToken
            } 
        });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/refresh-token', authenticateToken, async (req, res) => { 
    try {
        const { token } = req.body;

        if(!token) {
            return res.status(401).json({ message: 'Refresh token is required' });
        }

        const refreshToken = await userRefreshTokens.findOne({ token });
        if(!refreshToken) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        jwt.verify(token, config.refreshTokenSecret, async (err, tokenPayload) => {
            if(err) return res.sendStatus(403);

            await userRefreshTokens.remove({ _id: refreshToken._id });
            await userRefreshTokens.compactDatafile();

            const accessToken = jwt.sign({ id: tokenPayload._id, email: tokenPayload.email }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiration });
            const newRefreshToken = jwt.sign({ id: tokenPayload._id, email: tokenPayload.email }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });

            // Store the refresh token in the database
            await userRefreshTokens.insert({ token: newRefreshToken, userId: tokenPayload._id });

            return res.status(200).json({ 
                message: 'Access token refreshed successfully', 
                accessToken,
                newRefreshToken
            });
        });
    }
    catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/login/2fa/verify-temp-token', async (req, res) => {
    try {
        const { tempToken, totp } = req.body;

        if(!tempToken || !totp) {
            return res.status(422).json({ message: 'Please provide the temp token and OTP' });
        }

        const userId = cache.get(config.cacheTemporaryTokenPrefx + tempToken);
        if(!userId) {
            return res.status(403).json({ message: 'Invalid temp token' });
        }

        const user = await users.findOne({ _id: userId });
        if(!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const isValid = authenticator.check(totp, user['2faSecret']);
        if(!isValid) {
            return res.status(401).json({ message: 'Invalid OTP' });
        }

        cache.del(config.cacheTemporaryTokenPrefx + tempToken);

        const accessToken = jwt.sign({ id: user._id, email: user.email }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiration });
        const refreshToken = jwt.sign({ id: user._id, email: user.email }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiration });

        // Store the refresh token in the database
        await userRefreshTokens.insert({ token: refreshToken, userId: user._id });
        userRefreshTokens.compactDatafile();

        return res.status(200).json({ 
            message: 'User logged in successfully', 
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken,
                refreshToken
            } 
        });
    }catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

app.get('/api/auth/2fa/generate', authenticateToken, async (req, res) => {
    try{
        const user = await users.findOne({ _id: req.user.id });
        if(!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, 'MyApp', secret);
        console.log('URI:', uri);
        const qrCode = await QRCode.toBuffer(uri, { type: 'image/png', margin: 1 });

        await users.update({ _id: user._id }, { $set: { '2faSecret': secret, '2faEnabled': true } });
        await users.compactDatafile();

        res.setHeader('Content-Disposition', 'attachment; filename="qrcode.png"');
        return res.status(200).type('image/png').send(qrCode);
    }catch(err) {
        return res.status(500).json({ message: err.message });
    }
 });

app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
    try {
        //time-based one-time password
        const { totp } = req.body;

        if(!totp) {
            return res.status(422).json({ message: 'Please provide the OTP' });
        }

        const user = await users.findOne({ _id: req.user.id });
        if(!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const isValid = authenticator.check(totp, user['2faSecret']);
        if(!isValid) {
            return res.status(401).json({ message: 'Invalid OTP' });
        }

        return res.status(200).json({ message: 'OTP verified successfully' });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

//this will logout the user from all devices
app.get('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        await userRefreshTokens.removeMany({ userId: req.user.id });
        await userRefreshTokens.compactDatafile();

        await userInvalidTokens.insert({ token: req.accessToken.value, userId: req.user.id, expirationTime: req.accessToken.exp });
        await userInvalidTokens.compactDatafile();

        return res.status(200).json({ message: 'User logged out successfully' });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

// profile route
// this route is protected and requires a valid token to access
app.get('/api/auth/user', authenticateToken, async (req, res) => {
    try {
        console.log(req.user);
        const user = await users.findOne({ _id: req.user.id });
        if(!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        return res.status(200).json({ 
            message: 'User found', 
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            } 
        });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

app.get('/api/auth/admin/dashboard', authenticateToken, authorizeRoles(['admin']), async (req, res) => {

    try {

        return res.status(200).json({ 
            message: 'Admin dashboard: only admin can access this route',
            user: {
                id: req.user._id,
                name:req.user.name,
                email: req.user.email
            } 
        });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

app.get('/api/auth/moderator/dashboard', authenticateToken, authorizeRoles(['admin', 'moderator']), async (req, res) => {

    try {

        return res.status(200).json({ 
            message: 'Admin dashboard: only admin & moderator can access this route',
            user: {
                id: req.user._id,
                name:req.user.name,
                email: req.user.email
            } 
        });

    } catch(err) {
        return res.status(500).json({ message: err.message });
    }
});

// Middleware to authorize roles
// This middleware checks if the user has the required role to access the route
/* 
When you call authorizeRoles(['admin', 'moderator']), you are invoking the authorizeRoles function with specific roles. 
This function returns a new middleware function (an anonymous async function) that "remembers" the roles you passed in, 
thanks to JavaScript closures. 
This returned function is then used as the actual middleware in the route, where it checks if the authenticated user
 has one of the allowed roles.

On the other hand, authenticateToken is already a middleware function and is passed directly as a callback to the route.
 It does not need to be called to generate a new function; it is used as-is.

So, authorizeRoles is a middleware factory (returns a middleware using closure), 
while authenticateToken is a middleware function itself.
*/
function authorizeRoles(roles = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return async (req, res, next) => {
        const user = await users.findOne({ _id: req.user.id });
        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access Denied' });
        }
        req.user = user;
        next();
    };
}

// Middleware to authenticate token
// This middleware checks if the token is valid and if the user is authorized to access the route
async function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if(!token) return res.sendStatus(401);

    if(await userInvalidTokens.findOne({ token })) {
        return res.status(403).json({ message: 'Token is invalid' });
    }

    jwt.verify(token, config.accessTokenSecret, (err, tokenPayload) => {
        if(err) return res.sendStatus(403).json({ message: 'Invalid token'});
        req.accessToken = { value: token, exp: tokenPayload.exp };
        req.user = { id: tokenPayload.id };
        next();
    });
}

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});  