const jwt = require("jsonwebtoken");
const util = require("util");

const { SECRET, TOKEN_EXP } = process.env;

// Using promisfy util so that async/await syntax may be used with sign and
// verify methods.
jwt.sign = util.promisify(jwt.sign);
jwt.verify = util.promisify(jwt.verify);

const signToken = (user) => {
  // TODO: You customize the data encoded within the token adding/removing
  // properties from data.
  const data = {
    _id: user._id,
    email: user.email,
    username: user.username,
  };
  return jwt.sign({ data }, SECRET, {
    expiresIn: TOKEN_EXP,
  });
};

// Route level middleware. Use this on routes to send an error if a valid jwt is not included.
const requireAuth = async (req, res, next) => {
  if (req.user) {
    // User is defined (assuming authMiddleware was called first). Proceed to route.
    next();
    return;
  }
  res.status(401).json({ message: "Token missing or invalid." });
};

const expressAuthMiddleware = async (req, res, next) => {
  let token = req.body.token || req.query.token || req.headers.authorization;

  // We split the token string into an array and return actual token
  if (req.headers.authorization) {
    token = token.split(" ").pop().trim();
  }

  if (!token) {
    // no token so let next middleware/route handle the request without req.user
    return next();
  }

  try {
    // The next line throws if the token is not valid.
    const { data } = await jwt.verify(token, SECRET, { maxAge: TOKEN_EXP });

    // Add user data to req.user so that it can be accessed in other routes/middleware
    req.user = data;
  } catch (err) {
    console.log(`Invalid token received. Token: "${token}"`);
  }

  next();
};

const authMiddleware = async ({ req }) => {
  // allows token to be sent via req.body, req.query, or headers
  let token = req.body.token || req.query.token || req.headers.authorization;

  // We split the token string into an array and return actual token
  if (req.headers.authorization) {
    token = token.split(" ").pop().trim();
  }

  if (!token) {
    return req;
  }

  // if token can be verified, add the decoded user's data to the request so it can be accessed in the resolver
  try {
    const { data } = await jwt.verify(token, SECRET, { maxAge: TOKEN_EXP });
    req.user = data;
  } catch (err) {
    console.log(`Invalid token received. Token: "${token}"`);
  }

  // return the request object so it can be passed to the resolver as `context`
  return req;
};

module.exports = {
  signToken,
  authMiddleware,
  expressAuthMiddleware,
  requireAuth
};
