# HKAPI - Event Registration and Management API

HKAPI is a Node.js-based API for managing user registrations, event registrations, and QR code-based event check-ins. It includes user authentication, email verification, and session management.

## Features

- User registration with email verification
- Login with email or registration number
- Session-based authentication
- Event creation and registration
- QR code generation for event check-ins
- API endpoints for managing users, events, and registrations

## Prerequisites

- Node.js (v14 or higher)
- MongoDB
- Environment variables configured in a `.env` file

## Environment Variables

Create a `.env` file in the root directory and include the following variables:

```
EMAIL_USER=<your-email>
EMAIL_PASS=<your-email-password>
FRONTEND_URL=<frontend-url>
JWT_SECRET=<your-jwt-secret>
SESSION_SECRET=<your-session-secret>
MONGO_PASSWORD=<your-mongo-password>
MONGO_URI=<your-mongo-uri>
```

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/hk-srm/hero.git
   cd hkapi
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the server:

   ```bash
   npm start
   ```

4. The server will run on `http://localhost:3000` or a network-accessible address.

## API Endpoints

### Authentication

- `POST /api/signup` - Register a new user
- `GET /api/verify` - Verify email with a token
- `POST /api/login` - Login with email or registration number
- `POST /api/logout` - Logout and destroy session
- `GET /api/check-session` - Check active session

### User Management

- `GET /api/profile` - Get user profile

### Event Management

- `GET /api/events` - Get all events
- `POST /api/register-event/:eventId` - Register for an event
- `GET /api/my-events` - Get registered events
- `POST /api/scan` - Scan QR code for event check-in

## Folder Structure

```
hkapi/
├── public/          # Static files (HTML, CSS)
├── .env             # Environment variables
├── api.js           # Main server file
├── README.md        # Project documentation
└── package.json     # Project dependencies
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or support, please contact the project maintainer.
