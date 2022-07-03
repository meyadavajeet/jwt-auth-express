const express = require("express");
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

// creating fake user for seeding. we are not using db here
const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false
  }
];




app.listen(5000, () => console.log("Backend server is running"));


let refreshTokens = [];
/**
* login system with jwt auth
*/
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password
  });
  if (user) {
    // res.json(user);
    /*generate access token*/
    const accessToken = generateAccessToken(user);

    /*generate refresh token*/
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      token: accessToken,
      refreshToken: refreshToken
    });
  } else {
    res.status(400).json("Incorrect username or password !!!");
  }
});

/**
* Verify Bearer jsonwebtoken
* middleware for verify jwt token
*/
const verify = (req, res, next) => {
  const authHeader = req.headers.token;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "MySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!!!");
      }
      req.user = user;
      next();
    })
  } else {
    res.status(401).json("You are not authhenticated!");
  }
};

/**
 * refresh token for the authenticated users
 */

app.post('/api/refreshToken', (req, res) => {
  //take the refresh token from the user
  const refreshToken = req.body.token;

  //send error if there is no token or it's invalid
  if (!refreshToken) {
    return res.status(401).json("You are not authenticated");
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Invalid refresh token of Refresh token is not valid!!!");
  }
  jwt.verify(refreshToken, "MyRefreshSecretKey", (err, user) => {
    err && console.log(err);

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    //create new access token
    const newAccessToken = generateAccessToken(user);
    //create new refresh token
    const newRefreshToken = generateRefreshToken(user);
    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      token: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });

  //if everything is ok, create new access token, refresh token and send it back to user

})



/**
 * generating Access Token
 * */
const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "MySecretKey", { expiresIn: "15m" });
}

/**
 * refreshing Access Token
 * */
const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "MyRefreshSecretKey");
}


/**
*delete route
*/
app.delete("/api/deleteUser/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted.");
  } else {
    res.status(403).json("You are not allowed to delete this user!!!");
  }
});

/**
 * logout
 */
app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("User has been logged out successfully!!!");
});
