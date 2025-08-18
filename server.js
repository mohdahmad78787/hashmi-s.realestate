const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const sharp = require('sharp');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Check for required environment variables
if (!process.env.JWT_SECRET || !process.env.SESSION_SECRET) {
    console.error('❌ Missing required environment variables. Please check your .env file.');
    console.error('Required: JWT_SECRET, SESSION_SECRET');
    process.exit(1);
}

console.log('🚀 Starting Real Estate Platform...');


// Middleware
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

// MongoDB connection tracking
let isMongoConnected = false;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/realestate', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
}).then(() => {
    console.log('✅ Connected to MongoDB Atlas');
    isMongoConnected = true;
}).catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.warn('⚠️ Running without database - some features will be limited');
});

// Session store
let sessionStore;
if (process.env.MONGODB_URI) {
    try {
        sessionStore = MongoStore.create({
            mongoUrl: process.env.MONGODB_URI,
            touchAfter: 24 * 3600
        });
        console.log('✅ MongoDB session store configured');
    } catch (error) {
        console.warn('⚠️ MongoDB session store failed, using memory store');
    }
} else {
    console.warn('⚠️ No MONGODB_URI, using memory session store');
}

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    name: 'realestate.sid',
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));

console.log('✅ Session middleware configured');

// Schemas
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    userId: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'seller', 'customer'], required: true },
    address: String,
    contactDetails: String,
    isVerified: { type: Boolean, default: false },
    isBlacklisted: { type: Boolean, default: false },
    otp: String,
    otpExpiry: Date,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

const propertySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    physicalAddress: { type: String, required: true },
    city: { type: String }, // Added for city-based search
    googleMapLocation: {
        latitude: Number,
        longitude: Number,
        address: String
    },
    images: [String],
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    questions: [{
        customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        question: String,
        aiResponse: String,
        timestamp: { type: Date, default: Date.now }
    }],
    interestedBuyers: [{
        customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        timestamp: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Property = mongoose.model('Property', propertySchema);

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Email configuration (FIXED)
let transporter = null;
let emailEnabled = false;

function setupEmail() {
    try {
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            transporter = nodemailer.createTransport({ // FIXED: was createTransporter
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });
            emailEnabled = true;
            console.log('✅ Email service configured');
        } else {
            console.warn('⚠️ Email not configured - email features will be disabled');
        }
    } catch (error) {
        console.error('❌ Email configuration error:', error.message);
    }
}

setupEmail();

// Helper functions
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendEmail = async (to, subject, html) => {
    if (!emailEnabled || !transporter) {
        console.warn('⚠️ Email not sent (service not configured)');
        return true;
    }
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to,
            subject,
            html
        });
        console.log('✅ Email sent successfully to:', to);
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
};

// Calculate distance between two coordinates
const calculateDistance = (lat1, lon1, lat2, lon2) => {
    const R = 6371; // Earth's radius in kilometers
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    if (!req.session) {
        console.error('❌ Session not available');
        return res.status(500).json({ error: 'Session not configured properly' });
    }

    const token = req.session.token;
    if (!token) {
        return res.status(401).json({ error: 'Access denied - no token' });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Database check middleware
const requireDatabase = (req, res, next) => {
    if (!isMongoConnected) {
        return res.status(503).json({ error: 'Database not available. Please check your MongoDB connection.' });
    }
    next();
};

// ROUTES

// Serve main pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard/:role', authenticateToken, (req, res) => {
    const role = req.params.role;
    if (req.user.role !== role) {
        return res.status(403).json({ error: 'Access denied' });
    }
    res.sendFile(path.join(__dirname, 'public', `${role}-dashboard.html`));
});

// Health check
app.get('/api/health', async (req, res) => {
    res.json({
        status: 'ok',
        database: isMongoConnected ? 'connected' : 'disconnected',
        email: emailEnabled ? 'enabled' : 'disabled',
        timestamp: new Date().toISOString()
    });
});

// Auth routes
app.post('/api/register', requireDatabase, async (req, res) => {
    try {
        const { name, userId, email, password, address, contactDetails } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ userId }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User ID or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const otp = generateOTP();
        
        const user = new User({
            name,
            userId,
            email,
            password: hashedPassword,
            role: 'customer',
            address,
            contactDetails,
            otp,
            otpExpiry: new Date(Date.now() + 10 * 60 * 1000)
        });

        await user.save();

        const emailSent = await sendEmail(
            email,
            'Verify Your Email - Real Estate Platform',
            `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Email Verification Required</h2>
                <p>Your OTP for email verification is:</p>
                <div style="background: #007bff; color: white; padding: 20px; text-align: center; font-size: 24px; border-radius: 5px;">
                    <strong>${otp}</strong>
                </div>
                <p style="color: #666;">This OTP will expire in 10 minutes.</p>
            </div>`
        );

        if (!emailSent) {
            console.warn('⚠️ Email failed to send but registration completed');
        }

        res.json({ message: 'Registration successful. Please check your email for OTP verification.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/verify-otp', requireDatabase, async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        if (user.otp !== otp || user.otpExpiry < new Date()) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpiry = undefined;
        await user.save();

        res.json({ message: 'Email verified successfully. You can now login.' });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.post('/api/login', requireDatabase, async (req, res) => {
    try {
        const { userId, password } = req.body;
        
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        if (user.isBlacklisted) {
            return res.status(403).json({ error: 'Account has been suspended. Please contact administrator.' });
        }

        if (!user.isVerified && user.role === 'customer') {
            return res.status(400).json({ error: 'Please verify your email first' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id, userId: user.userId, role: user.role, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        req.session.token = token;
        req.session.user = {
            id: user._id,
            userId: user.userId,
            role: user.role,
            name: user.name
        };

        res.json({
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                role: user.role
            },
            redirectUrl: `/dashboard/${user.role}`
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get current user profile
app.get('/api/user/profile', authenticateToken, requireDatabase, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -otp');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, requireDatabase, async (req, res) => {
    try {
        const { name, email, address, contactDetails } = req.body;
        const updateData = { name, email, address, contactDetails };

        const user = await User.findByIdAndUpdate(req.user.id, updateData, { new: true }).select('-password -otp');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully', user });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Get user's interests
app.get('/api/user/interests', authenticateToken, requireDatabase, async (req, res) => {
    try {
        const properties = await Property.find({
            'interestedBuyers.customerId': req.user.id
        }).populate('sellerId', 'name contactDetails email');

        res.json(properties);
    } catch (error) {
        console.error('Get interests error:', error);
        res.status(500).json({ error: 'Failed to fetch interests' });
    }
});

// Get user's enquiries
app.get('/api/user/enquiries', authenticateToken, requireDatabase, async (req, res) => {
    try {
        const properties = await Property.find({
            'questions.customerId': req.user.id
        }).populate('sellerId', 'name contactDetails email');

        const enquiries = [];
        properties.forEach(property => {
            property.questions.forEach(q => {
                if (q.customerId.toString() === req.user.id) {
                    enquiries.push({
                        propertyId: property._id,
                        propertyTitle: property.title,
                        question: q.question,
                        aiResponse: q.aiResponse,
                        timestamp: q.timestamp,
                        seller: property.sellerId
                    });
                }
            });
        });

        res.json(enquiries);
    } catch (error) {
        console.error('Get enquiries error:', error);
        res.status(500).json({ error: 'Failed to fetch enquiries' });
    }
});

// Property search with radius and city filters
app.get('/api/properties/search', requireDatabase, async (req, res) => {
    try {
        const { latitude, longitude, radius, city, minPrice, maxPrice } = req.query;
        
        let query = {};
        
        // Price range filter
        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice) query.price.$gte = parseFloat(minPrice);
            if (maxPrice) query.price.$lte = parseFloat(maxPrice);
        }
        
        // City filter
        if (city) {
            query.$or = [
                { city: new RegExp(city, 'i') },
                { physicalAddress: new RegExp(city, 'i') },
                { 'googleMapLocation.address': new RegExp(city, 'i') }
            ];
        }
        
        let properties = await Property.find(query).populate('sellerId', 'name contactDetails');
        
        // Radius filter
        if (latitude && longitude && radius) {
            const lat = parseFloat(latitude);
            const lng = parseFloat(longitude);
            const radiusKm = parseFloat(radius);
            
            properties = properties.filter(property => {
                if (property.googleMapLocation && 
                    property.googleMapLocation.latitude && 
                    property.googleMapLocation.longitude) {
                    
                    const distance = calculateDistance(
                        lat, lng,
                        property.googleMapLocation.latitude,
                        property.googleMapLocation.longitude
                    );
                    return distance <= radiusKm;
                }
                return false;
            });
        }
        
        res.json(properties);
    } catch (error) {
        console.error('Property search error:', error);
        res.status(500).json({ error: 'Failed to search properties' });
    }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const users = await User.find({}).select('-password -otp').populate('createdBy', 'name');
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/admin/create-seller', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { name, userId, email, password, address, contactDetails } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ userId }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User ID or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const seller = new User({
            name,
            userId,
            email,
            password: hashedPassword,
            role: 'seller',
            address,
            contactDetails,
            isVerified: true,
            createdBy: req.user.id
        });

        await seller.save();

        res.json({
            message: 'Seller created successfully',
            seller: {
                id: seller._id,
                name,
                userId,
                email
            }
        });
    } catch (error) {
        console.error('Create seller error:', error);
        res.status(500).json({ error: 'Failed to create seller' });
    }
});

app.put('/api/admin/users/:id', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { name, email, address, contactDetails, userId, password, isBlacklisted } = req.body;
        
        const existingUser = await User.findOne({
            $or: [{ userId }, { email }],
            _id: { $ne: req.params.id }
        });
        
        if (existingUser) {
            return res.status(400).json({ error: 'User ID or email already exists' });
        }

        const updateData = { name, email, address, contactDetails, userId, isBlacklisted };
        
        if (password && password.trim() !== '') {
            updateData.password = await bcrypt.hash(password, 12);
        }

        const user = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, select: '-password -otp' }
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User updated successfully', user });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete user's properties if they're a seller
        if (user.role === 'seller') {
            await Property.deleteMany({ sellerId: user._id });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Change admin password
app.put('/api/admin/change-password', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { currentPassword, newPassword } = req.body;
        
        const admin = await User.findById(req.user.id);
        if (!admin) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        const isValidPassword = await bcrypt.compare(currentPassword, admin.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 12);
        admin.password = hashedNewPassword;
        await admin.save();

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Property routes
app.post('/api/properties', authenticateToken, requireDatabase, upload.array('images', 10), async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { title, description, price, physicalAddress, latitude, longitude, mapAddress } = req.body;
        
        // Process uploaded images
        const imagePromises = req.files.map(async (file) => {
            const processedPath = `uploads/processed-${file.filename}`;
            await sharp(file.path)
                .resize(800, 600, { fit: 'cover' })
                .jpeg({ quality: 80 })
                .toFile(processedPath);
            
            // Delete original file
            fs.unlinkSync(file.path);
            return processedPath;
        });

        const images = await Promise.all(imagePromises);
        
        // Extract city from address
        const city = physicalAddress.split(',').pop().trim();

        const property = new Property({
            title,
            description,
            price: parseFloat(price),
            physicalAddress,
            city,
            googleMapLocation: {
                latitude: parseFloat(latitude),
                longitude: parseFloat(longitude),
                address: mapAddress
            },
            images,
            sellerId: req.user.id
        });

        await property.save();

        res.json({ message: 'Property created successfully', property });
    } catch (error) {
        console.error('Create property error:', error);
        res.status(500).json({ error: 'Failed to create property' });
    }
});

app.get('/api/properties', requireDatabase, async (req, res) => {
    try {
        const properties = await Property.find()
            .populate('sellerId', 'name contactDetails')
            .sort({ createdAt: -1 });
        res.json(properties);
    } catch (error) {
        console.error('Get properties error:', error);
        res.status(500).json({ error: 'Failed to fetch properties' });
    }
});

app.get('/api/properties/:id', requireDatabase, async (req, res) => {
    try {
        const property = await Property.findById(req.params.id)
            .populate('sellerId', 'name contactDetails email')
            .populate('questions.customerId', 'name')
            .populate('interestedBuyers.customerId', 'name email contactDetails');

        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        res.json(property);
    } catch (error) {
        console.error('Get property error:', error);
        res.status(500).json({ error: 'Failed to fetch property' });
    }
});

app.delete('/api/properties/:id', authenticateToken, requireDatabase, async (req, res) => {
    try {
        const property = await Property.findById(req.params.id);
        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Check if user owns the property or is admin
        if (req.user.role !== 'admin' && property.sellerId.toString() !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Delete associated images
        property.images.forEach(imagePath => {
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        });

        await Property.findByIdAndDelete(req.params.id);

        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Delete property error:', error);
        res.status(500).json({ error: 'Failed to delete property' });
    }
});

// AI Question-Answer route
app.post('/api/properties/:id/ask', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'customer') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { question } = req.body;
        const property = await Property.findById(req.params.id);
        
        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Call AI service
        try {
            const axios = require('axios');
            const aiResponse = await axios.post(`${process.env.AI_SERVICE_URL || 'http://localhost:5000'}/ask`, {
                question,
                propertyData: {
                    title: property.title,
                    description: property.description,
                    price: property.price,
                    address: property.physicalAddress,
                    location: property.googleMapLocation
                }
            });

            const questionData = {
                customerId: req.user.id,
                question,
                aiResponse: aiResponse.data.answer,
                timestamp: new Date()
            };

            property.questions.push(questionData);
            await property.save();

            res.json({ answer: aiResponse.data.answer });
        } catch (aiError) {
            console.error('AI service error:', aiError);
            
            // Fallback response
            const fallbackAnswer = `Thank you for your interest in ${property.title}. This property is located at ${property.physicalAddress} and is priced at ₹${property.price.toLocaleString()}. For more specific information about your question, please contact our seller directly.`;
            
            const questionData = {
                customerId: req.user.id,
                question,
                aiResponse: fallbackAnswer,
                timestamp: new Date()
            };

            property.questions.push(questionData);
            await property.save();

            res.json({ answer: fallbackAnswer });
        }
    } catch (error) {
        console.error('Ask question error:', error);
        res.status(500).json({ error: 'Failed to process question' });
    }
});

// Express interest route
app.post('/api/properties/:id/interest', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'customer') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const property = await Property.findById(req.params.id).populate('sellerId');
        const customer = await User.findById(req.user.id);

        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Check if already interested
        const alreadyInterested = property.interestedBuyers.some(
            buyer => buyer.customerId.toString() === req.user.id
        );

        if (alreadyInterested) {
            return res.status(400).json({ error: 'You have already expressed interest in this property' });
        }

        // Add to interested buyers
        property.interestedBuyers.push({ customerId: req.user.id });
        await property.save();

        // Send email to seller
        const emailSent = await sendEmail(
            property.sellerId.email,
            'New Interest in Your Property',
            `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">New Customer Interest!</h2>
                <p><strong>Property:</strong> ${property.title}</p>
                <p><strong>Customer Details:</strong></p>
                <ul>
                    <li>Name: ${customer.name}</li>
                    <li>Email: ${customer.email}</li>
                    <li>Contact: ${customer.contactDetails}</li>
                    <li>Address: ${customer.address}</li>
                </ul>
                <p>Please contact the customer to proceed with the sale.</p>
            </div>`
        );

        res.json({
            message: 'Interest expressed successfully. The seller will contact you soon.',
            sellerContact: property.sellerId.contactDetails
        });
    } catch (error) {
        console.error('Express interest error:', error);
        res.status(500).json({ error: 'Failed to express interest' });
    }
});

// Get seller's properties with interested buyers and questions
app.get('/api/seller/properties', authenticateToken, requireDatabase, async (req, res) => {
    try {
        if (req.user.role !== 'seller') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const properties = await Property.find({ sellerId: req.user.id })
            .populate('questions.customerId', 'name email contactDetails address')
            .populate('interestedBuyers.customerId', 'name email contactDetails address')
            .sort({ createdAt: -1 });

        res.json(properties);
    } catch (error) {
        console.error('Get seller properties error:', error);
        res.status(500).json({ error: 'Failed to fetch properties' });
    }
});

// Logout route
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Initialize admin user
const initializeAdmin = async () => {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            const admin = new User({
                name: 'System Administrator',
                userId: 'admin',
                email: 'admin@realestate.com',
                password: hashedPassword,
                role: 'admin',
                isVerified: true
            });
            await admin.save();
            console.log('✅ Admin user created - UserId: admin, Password: admin123');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
};

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    initializeAdmin();
});
