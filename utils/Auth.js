const User = require('../models/User');
const userToken = require('../models/UserToken');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { SECRET, REFRESHTOKENSECRET } = require('../config');
const passport = require('passport');

/**
 * @DESC To register the user (ADMIN,SUPER_ADMIN,USER)
 */
const userRegister = async (userDets, role, res) => {
  try {
    // Validate the username
    let usernameTaken = await validateUsername(userDets.username);
    if (!usernameTaken) {
      return res.status(400).json({
        message: `Username is already taken.`,
        success: false,
      });
    }

    // Validate the email
    let EmailRegistered = await validateEmail(userDets.email);

    if (!EmailRegistered) {
      return res.status(400).json({
        message: `Email is already taken.`,
        success: false,
      });
    }

    // Get the hashed password
    const password = await bcrypt.hash(userDets.password, 12);

    // create a new user
    const newUser = new User({
      ...userDets,
      password,
      role,
    });
    const newUserToken = new userToken({
      username: userDets.username,
    });
    await newUser.save();
    await newUserToken.save();
    return res.status(201).json({
      message: `Successfully Created`,
      success: true,
    });
  } catch (err) {
    console.log(err);
    // Implement logger function (winston)
    return res.status(500).json({
      message: `Unable to create account`,
      success: false,
    });
  }
};

const userLogin = async (userCreds, role, res) => {
  let { username, password } = userCreds;
  // If Username is in the DB
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).json({
      message: `Username not found`,
      success: false,
    });
  }

  //Check role
  if (user.role !== role) {
    return res.status(403).json({
      message: `Unauthorized`,
      success: false,
    });
  }

  // Check Password
  let isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    //Sign in the token and issue it to the user
    const accessToken = jwt.sign(
      {
        user_id: user._id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      SECRET,
      { algorithm: 'HS256', expiresIn: 120 }
    );

    const refreshToken = jwt.sign(
      {
        user_id: user._id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      REFRESHTOKENSECRET,
      { algorithm: 'HS256', expiresIn: 86400 }
    );

    let result = {
      username: user.username,
      role: user.role,
      email: user.email,
      accessToken,
      refreshToken,
      expiresIn: 120,
    };

    const tokens = { accessToken, refreshToken };
    res.cookie('jwt', accessToken, { secure: true, httpOnly: true });

    await userToken.findOneAndUpdate(
      { username: user.username },
      { $addToSet: { refreshToken } },
      { upsert: true },
      function (err, model) {
        if (err) console.log(err);
      }
    );
    return res.status(200).json({
      ...result,
      message: 'Hurray! You are now logged in.',
      success: true,
    });
  } else {
    return res.status(400).json({
      message: `Password Doesn't match`,
      success: false,
    });
  }
};

const validateUsername = async (username) => {
  let user = await User.findOne({ username });
  return user ? false : true;
};

const validateEmail = async (email) => {
  let user = await User.findOne({ email });
  return user ? false : true;
};

/**
 * @Desc Passport middleware
 */
const userAuth = passport.authenticate('jwt', { session: false });

const serializeUser = (user) => {
  return {
    username: user.username,
    email: user.email,
    name: user.name,
    _id: user._id,
    updatedAt: user.updatedAt,
    createdAt: user.createdAt,
  };
};

/**
 * @Desc Check role Middleware
 */
const checkRole = (roles) => (req, res, next) =>
  roles.includes(req.user.role)
    ? next()
    : res.status(401).json({
        message: `Unauthorized`,
      });

const token = async (req, res) => {
  try {
    const { token } = req;
    payload = jwt.verify(token, REFRESHTOKENSECRET);
    const user = await userToken.findOne({ username: payload.username });
    const REFRESHTOKENS = user.refreshToken;
    if (!token) {
      return res.sendStatus(401);
    }

    if (!REFRESHTOKENS.includes(token)) {
      return res.sendStatus(403);
    }

    jwt.verify(token, REFRESHTOKENSECRET, async (err, userJWT) => {
      if (err) {
        return res.sendStatus(403);
      }
      const user = await User.findOne({ username: userJWT.username });
      const accessToken = jwt.sign(
        {
          user_id: user._id,
          role: user.role,
          username: user.username,
          email: user.email,
        },
        SECRET,
        { algorithm: 'HS256', expiresIn: 120 }
      );

      return res.status(200).json({
        accessToken,
      });
    });
  } catch (err) {
    console.log(err);
    // Implement logger function (winston)
    return res.status(500).json({
      message: `Invalid Token`,
      success: false,
    });
  }
};

const logout = async (req, res) => {
  const { token } = req.body;
  payload = jwt.verify(token, REFRESHTOKENSECRET);
  const user = await userToken.findOne({ username: payload.username });
  const REFRESHTOKENS = user.refreshToken;
  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, REFRESHTOKENSECRET, async (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    if (!REFRESHTOKENS.includes(token)) {
      return res.status(404).json({
        message: `Error logout! Login Again`,
      });
    }

    await userToken.findOneAndUpdate(
      { username: user.username },
      { $pullAll: { refreshToken: [token] } },
      { upsert: true },
      function (err, model) {
        if (err) console.log(err);
      }
    );
    res.send('Logout successful');
  });
};

module.exports = {
  userAuth,
  userRegister,
  userLogin,
  serializeUser,
  checkRole,
  token,
  logout,
};
