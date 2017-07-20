const express    = require('express');
const passport   = require('passport');
const bcrypt     = require('bcrypt');

// Our user model
const User       = require('../models/UserModel');
const authRoutes = express.Router();

//sign up
authRoutes.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    res.status(400).json({ message: 'Provide username and password' });
    return;
  }

  User.findOne({ username }, (err, foundUser) => {
    if (err) {
      res.status(500).json({message: "Username check failed"});
    }
    if (foundUser) {
      res.status(400).json({ message: 'The username already exists' });
      return;
    }

    const salt     = bcrypt.genSaltSync(10);
    const hashPass = bcrypt.hashSync(password, salt);

    const theUser = new User({
      username,
      password: hashPass
    });

    theUser.save((err) => {
      if (err) {
        res.status(400).json({ message: 'Something went wrong' });
        return;
      }
       //req.login is defined by password
      req.login(theUser, (err) => {
        if (err) {
          res.status(500).json({ message: 'Something went wrong' });
          return;
        }
        //remove password from the response
        theUser.password = undefined;
        res.status(200).json({message: "Login Succesful", userInfo: theUser});
      });
      }
    );
  });
});

//login
authRoutes.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, theUser, failureDetails) => {
    if (err) {
      res.status(500).json({ message: 'Something went wrong' });
      return;
    }

    if (!theUser) {
      //failureDetails contains feedback from passport local strategy
      res.status(401).json(failureDetails);
      return;
    }

    req.login(theUser, (err) => {
      if (err) {
        res.status(500).json({ message: 'Something went wrong' });
        return;
      }

      // We are now logged in
      res.status(200).json(theUser);
    });
  });
});

//logout
authRoutes.post('/logout', (req, res, next) => {
  req.logout();
  res.status(200).json({ message: 'Success' });
});

//check if user logged in
authRoutes.get('/loggedin', (req, res, next) => {
  if (req.isAuthenticated()) {
    res.status(200).json(req.user);
    return;
  }

  res.status(403).json({ message: 'Unauthorized' });
});

module.exports = authRoutes;
