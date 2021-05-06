const cors = require('cors');
const exp = require('express');
const bp = require('body-parser');
const { success, error } = require('consola');
const { connect } = require('mongoose');

const passport = require('passport');
//Bring in the app constants
const { DB, PORT } = require('./config');

//Initialize the application
const app = exp();

//Middlewares
app.use(bp.json());
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));

app.use(passport.initialize());

require('./middlewares/passport')(passport);
// User Router Middleware
app.use('/api/users', require('./routes/users'));

const startApp = async () => {
  try {
    //Connection with DB
    await connect(DB, {
      useFindAndModify: false,
      useUnifiedTopology: true,
      useNewUrlParser: true,
    });

    success({
      message: `Successfully connected to database\n ${DB}`,
      badge: true,
    });

    //Start Listening for the server on port
    app.listen(PORT, () =>
      success({ message: `Server started on POST ${PORT}`, badge: true })
    );
  } catch (err) {
    error({
      message: `Unable to connect with Database \n ${DB}`,
      badge: true,
    });
    startApp();
  }
};

startApp();
