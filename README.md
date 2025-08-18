# Real Estate Shopping Platform

A comprehensive real estate platform with admin, seller, and customer dashboards, featuring AI-powered property consultations and mobile-responsive design.

## Features

### Multi-Role System
- **Admin Dashboard**: Manage sellers and customers, view all properties, system analytics
- **Seller Dashboard**: Add/manage properties with GPS location, view inquiries and interested buyers
- **Customer Dashboard**: Browse properties, AI assistant for property questions, express interest

### Key Capabilities
- **AI Integration**: Gemini AI for property Q&A with fallback responses
- **Email Notifications**: OTP verification, buyer-seller notifications
- **Image Management**: Local file storage with image processing
- **GPS Location**: Real-time location detection for property mapping
- **Mobile Responsive**: Bootstrap-based responsive design
- **Secure Authentication**: JWT tokens, session management, password hashing

## Technology Stack

### Backend
- **Node.js** with Express.js
- **MongoDB Atlas** for database
- **JWT** for authentication
- **Multer & Sharp** for image handling
- **Nodemailer** for email services
- **bcryptjs** for password hashing

### Frontend
- **Vanilla HTML/CSS/JavaScript**
- **Bootstrap 5.3** for responsive UI
- **Font Awesome** for icons

### AI Service
- **Python Flask** application
- **Gemini API** integration
- **CORS** enabled for cross-origin requests

## Prerequisites

Before you begin, ensure you have:

1. **Node.js** (version 14 or higher)
2. **MongoDB Atlas** account and connection string
3. **Email account** with app password for notifications
4. **Gemini API key** (optional, for AI features)
5. **Python 3.9+** (for AI service)

## Installation & Setup

### 1. Clone and Install Dependencies

```bash
# Install main application dependencies
npm install
```

### 2. Environment Configuration

Create a `.env` file in the root directory:

```env
MONGODB_URI=mongodb+srv://your-username:your-password@cluster0.mongodb.net/realestate?retryWrites=true&w=majority
JWT_SECRET=your-super-secret-jwt-key-here-make-it-long-and-random
SESSION_SECRET=your-session-secret-key-here
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
PORT=3000
AI_SERVICE_URL=https://your-python-service.replit.dev
GEMINI_API_KEY=your-gemini-api-key-here
```

### 3. MongoDB Setup

1. Create a MongoDB Atlas account at https://mongodb.com/atlas
2. Create a new cluster
3. Create a database user
4. Get your connection string
5. Replace `your-username` and `your-password` in the MONGODB_URI

### 4. Email Setup (Gmail)

1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → App passwords
   - Generate password for "Mail"
3. Use this app password in EMAIL_PASS

### 5. Start the Application

```bash
# Start the main application
npm start

# For development with auto-restart
npm run dev
```

The application will be available at `http://localhost:3000`

### 6. Deploy AI Service (Optional)

#### Option A: Deploy to Railway/Heroku

1. Create account on Railway.app or Heroku
2. Deploy the `python-ai` folder
3. Set environment variable: `GEMINI_API_KEY=your-key`
4. Update `AI_SERVICE_URL` in your `.env` file

#### Option B: Deploy to Replit

1. Create new Repl on Replit.com
2. Upload files from `python-ai` folder
3. Set `GEMINI_API_KEY` in Secrets
4. Run the application
5. Use the provided URL in `AI_SERVICE_URL`

#### Option C: Local AI Service

```bash
cd python-ai
pip install -r requirements.txt
export GEMINI_API_KEY=your-api-key
python main.py
```

Update `.env`: `AI_SERVICE_URL=http://localhost:5000`

## Default Admin Account

The system automatically creates an admin account:
- **User ID**: `admin`
- **Password**: `admin123`

## Usage Guide

### For Beginners

1. **Start the application**: Run `npm start`
2. **Access the platform**: Open `http://localhost:3000`
3. **Admin login**: Use admin/admin123 to access admin panel
4. **Create sellers**: Use admin dashboard to create seller accounts
5. **Add properties**: Login as seller to add properties with images and GPS location
6. **Customer registration**: Customers can sign up and verify via email
7. **Browse properties**: Customers can view properties and ask AI questions

### Testing the Platform

1. **Admin Functions**:
   - Login with admin credentials
   - Create seller accounts
   - View all users and properties
   - Delete users/properties

2. **Seller Functions**:
   - Add properties with images
   - Use GPS location detection
   - View customer inquiries
   - Check interested buyers

3. **Customer Functions**:
   - Register and verify email
   - Browse and search properties
   - Ask AI questions about properties
   - Express interest in properties

## File Structure

```
real-estate-platform/
├── server.js                 # Main server file
├── package.json              # Dependencies and scripts
├── .env                      # Environment variables
├── public/                   # Frontend files
│   ├── index.html           # Homepage
│   ├── login.html           # Login page
│   ├── signup.html          # Registration page
│   ├── admin-dashboard.html # Admin interface
│   ├── seller-dashboard.html# Seller interface
│   └── customer-dashboard.html# Customer interface
├── uploads/                  # Image storage directory
├── python-ai/               # AI service
│   ├── main.py              # Flask application
│   ├── requirements.txt     # Python dependencies
│   ├── Procfile            # Deployment config
│   └── runtime.txt         # Python version
└── README.md                # This file
```

## API Endpoints

### Authentication
- `POST /api/register` - Customer registration
- `POST /api/verify-otp` - Email verification
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### Admin Routes
- `POST /api/admin/create-seller` - Create seller account
- `GET /api/admin/users` - Get all users
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user

### Property Routes
- `GET /api/properties` - Get all properties
- `GET /api/properties/:id` - Get property details
- `POST /api/properties` - Create property (seller only)
- `DELETE /api/properties/:id` - Delete property
- `GET /api/seller/properties` - Get seller's properties

### Customer Interaction
- `POST /api/properties/:id/ask` - Ask AI question
- `POST /api/properties/:id/interest` - Express interest

## Deployment Options

### Local Development
- Run with `npm start` or `npm run dev`
- Access at `http://localhost:3000`

### Production Deployment
1. **Railway.app**: Connect GitHub repo, set environment variables
2. **Heroku**: Use Git deployment with proper buildpacks
3. **DigitalOcean**: Deploy on droplets with PM2
4. **Vercel**: For frontend, separate backend deployment needed

## Troubleshooting

### Common Issues

1. **MongoDB Connection Error**:
   - Check MONGODB_URI format
   - Ensure IP whitelist includes your address
   - Verify database user permissions

2. **Email Not Sending**:
   - Confirm Gmail app password is correct
   - Check EMAIL_USER and EMAIL_PASS values
   - Ensure 2FA is enabled on Gmail

3. **Image Upload Fails**:
   - Check uploads directory exists and is writable
   - Verify file size limits (10MB max)
   - Ensure proper file types (images only)

4. **AI Service Unavailable**:
   - Application works without AI service (fallback responses)
   - Check AI_SERVICE_URL is correct
   - Verify Gemini API key is valid

### Development Tips

1. **Database Reset**: Delete all collections in MongoDB to start fresh
2. **Image Cleanup**: Regularly clean uploads folder in development
3. **Session Issues**: Clear browser data if login problems occur
4. **API Testing**: Use Postman or similar tools for API testing

## Security Considerations

- Change default admin password immediately
- Use strong JWT and session secrets
- Keep API keys secure and never commit to version control
- Implement rate limiting for production use
- Use HTTPS in production
- Validate and sanitize all user inputs
- Implement proper CORS policies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues and questions:
1. Check this README first
2. Review error logs in console
3. Verify all environment variables are set correctly
4. Test with minimal configuration first

## License

This project is open source and available under the MIT License.