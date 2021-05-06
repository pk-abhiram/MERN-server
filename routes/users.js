const router = require('express').Router();
// Bring in the user registration function
const {
  userRegister,
  userLogin,
  userAuth,
  serializeUser,
  checkRole,
  token,
  logout,
} = require('../utils/Auth');

//Users Registration Routes
router.post('/register-user', async (req, res) => {
  await userRegister(req.body, 'user', res);
});

//Admin Registration Routes
router.post('/register-admin', async (req, res) => {
  await userRegister(req.body, 'admin', res);
});

//SuperAdmin Registration Routes
router.post('/register-super-admin', async (req, res) => {
  await userRegister(req.body, 'superadmin', res);
});

//Users Login Routes
router.post('/login-user', async (req, res) => {
  await userLogin(req.body, 'user', res);
});

//Admin Login Routes
router.post('/login-admin', async (req, res) => {
  await userLogin(req.body, 'admin', res);
});

//SuperAdmin Login Routes
router.post('/login-super-admin', async (req, res) => {
  await userLogin(req.body, 'superadmin', res);
});

//Profile Route
router.get('/profile', userAuth, async (req, res) => {
  return res.json(serializeUser(req.user));
});

//Users Protected Routes
router.get(
  '/user-protected',
  userAuth,
  checkRole(['user']),
  async (req, res) => {
    return res.json('Hello User');
  }
);

//Admin Protected Routes
router.get(
  '/admin-protected',
  userAuth,
  checkRole(['admin']),
  async (req, res) => {
    return res.json('Hello User');
  }
);

//SuperAdmin Protected Routes
router.get(
  '/super-admin-protected',
  userAuth,
  checkRole(['superadmin']),
  async (req, res) => {
    return res.json('Hello User');
  }
);

//SuperAdmin and Admin Protected Routes
router.get(
  '/super-admin-and-admin-protected',
  userAuth,
  checkRole(['superadmin', 'admin']),
  async (req, res) => {
    return res.json('Hello User');
  }
);

//Refresh token
router.post('/token', async (req, res) => {
  await token(req.body, res);
});

//logout user

router.post('/logout', async (req, res) => {
  await logout(req, res);
});
module.exports = router;
