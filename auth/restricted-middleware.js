const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model.js');
const secrets = require('../config/secrets.js')

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  const { username, password } = req.headers;

  const secret = secrets.jwtSecret

  if (token) {
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        // token expired or invalid
        res.status(401).json({ message: 'You shall not pass!' });
      } else {
        // token is goooooooood!
        req.user = { username: decodedToken.username }
        next();
      }
    })
  } else {
    res.status(400).json({ message: 'no credentials provided'})
  }
}
