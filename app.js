var express = require("express");
var cors = require("cors");
var bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "dsme";
const HttpStatus = require("http-status-codes");
const {
  json
} = require("body-parser");

var app = express();
var jsonParser = bodyParser.json();
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
app.use(cors());
//connection database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "dsme",

});

app.get("/", jsonParser, function (req, res, next) {
  res.json({
    msg: "This is origins!",
  });
});

// Api Register
app.post("/register", jsonParser, function (req, res, next) {
  try { // Ger user input
    const {
      username,
      password,
      first_name,
      last_name,
      birthday
    } = req.body;

    //validate user input
    if (!(username && password && first_name && last_name && birthday)) {
      res.send({
        ok: false,
        message: "Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      bcrypt.hash(password, saltRounds, function (err, hash) {
        connection.execute(
          "INSERT INTO users(username, password, first_name, last_name, birthday) VALUES (?,?,?,?,?)",
          [username, hash, first_name, last_name, birthday],
          function (err, users, fields) {
            // check if user already exist
            // validate if user exist in our database
            if (err) {
              return res.send({
                ok: false,
                message: "Username already taken.",
                code: HttpStatus.StatusCodes.BAD_REQUEST,
                Text: err.message,
              });
            }
            res.send({
              ok: true,
              message: "Register success.",
              code: HttpStatus.StatusCodes.OK,
            });
          }
        );
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//Api Login
app.post("/login", jsonParser, function (req, res, next) {
  try {
    const {
      username,
      password
    } = req.body;
    if (!(username && password)) {
      res.json({
        ok: false,
        message: "Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "SELECT * FROM `users` WHERE  username = ?",
        [username],
        function (err, users, fields) {
          if (err) {
            res.json({
              ok: false,
              message: err,
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
          if (users.length == 0) {
            return res.json({
              ok: false,
              message: "Invalid username or password!.",
              code: HttpStatus.StatusCodes.UNAUTHORIZED,
            });
          }
          bcrypt.compare(password, users[0].password, function (err, result) {
            // result == true
            if (err) throw err;
            if (result) {
              var token = jwt.sign({
                  username: users[0].username,
                },
                secret, {
                  expiresIn: "1h",
                }
              );
              res.json({
                ok: true,
                message: "login success.",
                token,
                code: HttpStatus.StatusCodes.OK,
              });
            } else {
              res.json({
                ok: false,
                message: "Invalid username or password!.",
                code: HttpStatus.StatusCodes.UNAUTHORIZED,
              });
            }
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    res.send({
      ok: false,
      error: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

// Api authen check token
app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({
      ok: true,
      message: "success.",
      decoded,
      code: HttpStatus.StatusCodes.OK,
    });
  } catch (err) {
    res.json({
      ok: false,
      message: err.message,
      code: HttpStatus.StatusCodes.BAD_REQUEST,
    });
  }
});

app.listen(3000, function () {
  console.log("web server listening on port 3000");
});