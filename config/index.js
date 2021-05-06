require('dotenv').config();

module.exports = {
  DB: process.env.APP_DB,
  PORT: process.env.APP_PORT,
  SECRET: process.env.APP_SECRET,
  REFRESHTOKENSECRET: process.env.REFRESHTOKENSECRET,
};
