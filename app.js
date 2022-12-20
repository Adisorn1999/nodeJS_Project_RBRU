var express = require("express");
var cors = require("cors");
var bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "1EEA6DC-JAM4DP2-PHVYPBN-V0XCJ9X";
const HttpStatus = require("http-status-codes");
const { json } = require("body-parser");

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
  try {
    // Ger user input
    const { username, password, first_name, last_name, birthday } = req.body;

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
    const { username, password } = req.body;
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
              var token = jwt.sign(
                {
                  username: users[0].username,
                },
                secret,
                {
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

// get users
app.get("/users", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT `user_id`, `username`, `first_name`, `last_name`, `birthday` FROM `users`",
    (err, result, fields) => {
      if (err) throw err;
      res.json({
        ok: true,
        data: result,
      });
    }
  );
});

//get users by  user_id
app.get("/users/:id", jsonParser, function (req, res, next) {
  try {
    var id = req.params.id;
    connection.execute(
      "SELECT `user_id`, `username`, `first_name`, `last_name`, `birthday` FROM `users` WHERE user_id = ?",
      [id],
      (err, result, fields) => {
        if (err) throw err;
        if (id) {
          res.json({
            ok: true,
            data: result,
            code: HttpStatus.StatusCodes.OK,
          });
        }
      }
    );
  } catch (err) {
    // thow message error (command)
    console.log(err);
    res.json({
      ok: false,
      message: err.message,
      code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
    });
  }
});

app.get("/username/:name", jsonParser, function (req, res, next) {
  var name = req.params.name;
  connection.execute(
    "SELECT `user_id`, `username`, `first_name`, `last_name`, `birthday` FROM `users` WHERE username = ?",
    [name],
    (err, result, fields) => {
      if (err) throw err;
      if (result.length == 0) {
        res.json({
          ok: false,
          message: "User not found ",
          code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
        });
      } else {
        res.json({
          ok: true,
          result,
          code: HttpStatus.StatusCodes.OK,
        });
      }
    }
  );
});
// get blood sugar all
app.get("/bloods", jsonParser, function (req, res) {
  try {
    connection.execute("SELECT * FROM `blood`", (err, result) => {
      if (err) throw err;
      return res.json({
        ok: true,
        data: result,
        code: HttpStatus.StatusCodes.OK,
      });
    });
  } catch (err) {
    console.log(err);
  }
});
//get blood sugar by user_id
app.get("/blood/:id", jsonParser, (req, res) => {
  try {
    const id = req.params.id;
    connection.execute(
      "SELECT * FROM `blood` WHERE user_id = ?",
      [id],
      (err, result) => {
        if (err) throw err;
        return res.json({
          ok: true,
          data: result,
          code: HttpStatus.StatusCodes.OK,
        });
      }
    );
  } catch (err) {
    console.log(err);
  }
});
// add blood sugar
app.post("/blood/:id", jsonParser, function (req, res) {
  try {
    const { blood_level, blood_time } = req.body;
    const user_id = req.params.id;
    if (!(blood_level && blood_time && user_id)) {
      res.json({
        ok: false,
        message: "1Please complete the information.",
      });
    } else {
      connection.execute(
        "INSERT INTO `blood`( `blood_level`, `blood_time`, `user_id`) VALUES (?,?,?) ",
        [blood_level, blood_time, user_id],
        (err, users, fields) => {
          if (err) throw err;
          return res.send({
            ok: true,
            message: " success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (err) {
    console.log(err);
  }
});
//get medication all
app.get("/medications", jsonParser, (req, res) => {
  try {
    connection.execute(
      "SELECT * FROM `medication_warehouse`",
      (err, result) => {
        if (err) throw err;
        return res.json({
          ok: true,
          data: result,
          code: HttpStatus.StatusCodes.OK,
        });
      }
    );
  } catch (err) {
    console.log(err);
  }
});
// get medication by user_id
app.get("/medication/:id", jsonParser, (req, res) => {
  try {
    const id = req.params.id;
    connection.execute(
      "SELECT * FROM `medication_warehouse` WHERE user_id = ?",
      [id],
      (err, result, fields) => {
        if (err) throw err;
        return res.json({
          ok: true,
          data: result,
          code: HttpStatus.StatusCodes.OK,
        });
      }
    );
  } catch (err) {
    console.log(err);
  }
});
// add medication
app.post("/medication/:id", jsonParser, function (req, res) {
  try {
    const { medication_name, medication_amount, medication_time, time } =
      req.body;
    const user_id = req.params.id;
    if (!(medication_name, medication_amount, medication_time, time, user_id)) {
      res.json({
        ok: false,
        message: "1Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "INSERT INTO `medication_warehouse`( `medication_name`, `medication_amount`, `medication_time`, `time`, `user_id`) VALUES (?,?,?,?,?) ",
        [medication_name, medication_amount, medication_time, time, user_id],
        (err, users, fields) => {
          if (err) throw err;
          return res.send({
            ok: true,
            message: " success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(3000, function () {
  console.log("web server listening on port 3000");
});
