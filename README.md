# HKAPI

HKAPI is a Node.js-based backend application for user authentication, event registration, and QR code generation. It uses MongoDB as the database and Express.js for handling API requests.

## Repository

The source code for this project is hosted at: [https://github.com/hk-srm/hero.git](https://github.com/hk-srm/hero.git)

## File Structure

```
hkapi/
├── public/               # Frontend HTML files
│   ├── index.html        # Landing page
│   ├── login.html        # Login page
│   ├── profile.html      # User profile page
├── .env                  # Environment variables
├── .gitignore            # Git ignore file
├── api.js                # Main backend API file
├── package.json          # Node.js dependencies and scripts
└── README.md             # Project documentation
```

## API Endpoints

### Authentication Endpoints

#### `POST /api/signup`

- **Description**: Registers a new user.
- **Request Body**:
  ```json
  {
    "name": "John Doe",
    "email": "john@example.com",
    "registrationNumber": "12345",
    "password": "password123"
  }
  ```
- **Response**:
  - `200 OK`: User created and verification email sent.
  - `400 Bad Request`: Missing fields or duplicate email/registration number.

#### `POST /api/login`

- **Description**: Logs in a user.
- **Request Body**:
  ```json
  {
    "loginID": "john@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  - `200 OK`: Returns user details and sets a JWT token in cookies.
  - `400 Bad Request`: Invalid credentials.
  - `401 Unauthorized`: Account not verified.

#### `POST /api/logout`

- **Description**: Logs out the user by clearing the session and cookies.
- **Response**:
  - `200 OK`: Logout successful.

#### `GET /api/verify`

- **Description**: Verifies a user's email using a token.
- **Query Parameters**:
  - `token`: Verification token sent via email.
- **Response**:
  - `200 OK`: Email verified successfully.
  - `400 Bad Request`: Invalid token.

### Profile Endpoints

#### `GET /api/profile`

- **Description**: Fetches the authenticated user's profile and registered events.
- **Response**:
  - `200 OK`: Returns user details and registered events.
  - `401 Unauthorized`: User not authenticated.

### Event Endpoints

#### `GET /api/events`

- **Description**: Fetches all available events.
- **Response**:
  - `200 OK`: List of events.

#### `POST /api/register-event`

- **Description**: Registers the authenticated user for an event.
- **Request Body**:
  ```json
  {
    "eventId": "event123"
  }
  ```
- **Response**:
  - `200 OK`: Registration successful with a QR code.
  - `400 Bad Request`: Already registered for the event.

#### `GET /api/my-events`

- **Description**: Fetches events the authenticated user is registered for.
- **Response**:
  - `200 OK`: List of registered events.

#### `POST /api/scan`

- **Description**: Marks a QR code as scanned for event entry.
- **Request Body**:
  ```json
  {
    "qrToken": "user123-event123-1234567890"
  }
  ```
- **Response**:
  - `200 OK`: Entry granted.
  - `400 Bad Request`: QR code already used.
  - `404 Not Found`: Invalid QR token.

### Miscellaneous Endpoints

#### `GET /`

- **Description**: Serves the landing page or redirects to `/home` if authenticated.

#### `GET /home`

- **Description**: Serves the home page for authenticated users.

#### `GET /login`

- **Description**: Serves the login page.

#### `GET /logout`

- **Description**: Logs out the user and redirects to the login page.

### Environment Variables

The application requires the following environment variables to be set in a `.env` file:

- `EMAIL_USER`: Email address for sending verification emails.
- `EMAIL_PASS`: Password for the email account.
- `FRONTEND_URL`: Base URL of the frontend.
- `JWT_SECRET`: Secret key for signing JWT tokens.
- `SESSION_SECRET`: Secret key for session management.
- `MONGO_PASSWORD`: MongoDB password.
- `MONGO_URI`: MongoDB connection URI.

### Running the Application

1. Install dependencies:

   ```bash
   npm install
   ```

2. Start the server:

   ```bash
   npm start
   ```

3. For development with live reload:
   ```bash
   npm run dev
   ```

The server will run on `http://localhost:3000`.

### License

This project is licensed under the ISC License.
