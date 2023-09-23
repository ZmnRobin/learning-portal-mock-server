const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json'); // Assuming your data is in db.json
const middlewares = jsonServer.defaults();

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Import json-server-auth middleware
const auth = require('json-server-auth');

// Use json-server-auth middleware
server.db = router.db;
// server.use(router);
server.use(middlewares);
server.use(auth);

// Secret key for JWT
const JWT_SECRET_KEY = '9befdba07883c6f3cad4c01d52593c89f6faa7e8494c1bf232708bc607dac44b';

// Define a custom route for user registration
server.post('/register', (req, res) => {
  const { email, password, name } = req.body;

  // Check if the user with the same email already exists
  const existingUser = router.db
    .get('users')
    .find({ email })
    .value();

  if (existingUser) {
    return res.status(400).json({ message: 'User with this email already exists' });
  }

  // Generate a unique user ID (you can use a library like 'uuid' for this)
  const userId = generateUniqueId();

  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Create a new user object
  const newUser = {
    id: userId,
    email,
    password: hashedPassword,
    name,
    role: 'user', // Assuming a default role of 'user'
  };

  // Add the new user to the database
  router.db.get('users').push(newUser).write();

  // Create a JWT token
  const accessToken = jwt.sign({ id: userId, email, role: 'user' }, JWT_SECRET_KEY);

  // Respond with the user object and token
  res.status(200).json({ user: newUser, accessToken });
});

// Define a custom route for user login
server.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find the user with the provided email
  const user = router.db
    .get('users')
    .find({ email })
    .value();

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Verify the password
  const isPasswordValid = bcrypt.compareSync(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  // Create a JWT token
  const accessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET_KEY);

  // Respond with the user object and token
  res.status(200).json({ user, accessToken });
});

// Define a custom route for admin login
server.post('/admin/login', (req, res) => {
  const { email, password } = req.body;

  // Find the admin with the provided email
  const admin = router.db
    .get('users')
    .find({ email, role: 'admin' }) // Check for admin role
    .value();

  if (!admin) {
    return res.status(404).json({ message: 'Admin not found' });
  }

  // Verify the password
  const isPasswordValid = bcrypt.compareSync(password, admin.password);

  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  // Create a JWT token
  const accessToken = jwt.sign({ id: admin.id, email: admin.email, role: admin.role }, JWT_SECRET_KEY);

  // Respond with the admin object and token
  res.status(200).json({ admin, accessToken });
});

// Existing routes for assignments and videos are preserved by not redefining them here.

// Ensure that the JSON server router is registered last

server.use(router);

const port = process.env.PORT || 9000;

server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});

// Function to generate a unique user ID (you can use a library like 'uuid' for this)
function generateUniqueId() {
  // Implement your logic here to generate a unique ID
  return Math.random().toString(36).substr(2, 9);
}

