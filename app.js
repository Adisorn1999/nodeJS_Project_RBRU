const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const secret = "1EEA6DC-JAM4DP2-PHVYPBN-V0XCJ9X";
const HttpStatus = require("http-status-codes");
const { json } = require("body-parser");
const dotenv = require("dotenv").config();

var app = express();
var jsonParser = bodyParser.json();
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);
app.use(cors());

const connection = mysql.createConnection({
  host: process.env.DB_HOSTNAME,
  database: process.env.DB_NAME,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
});

app.get("/", jsonParser, function (req, res, next) {
  res.json({
    msg: "This is origins!",
  });
});

// Api Register User
app.post("/register", jsonParser, function (req, res, next) {
  try {
    // Ger user input
    const { username, password, first_name, last_name, birthday, gender } =
      req.body;

    //validate user input
    if (!(username && password && first_name && last_name && birthday)) {
      res.json({
        ok: false,
        message: "Please complete the information (register).",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      bcrypt.hash(password, saltRounds, function (err, hash) {
        connection.execute(
          "INSERT INTO users(username, password, first_name, last_name, birthday, gender) VALUES (?,?,?,?,?,?)",
          [username, hash, first_name, last_name, birthday, gender],
          function (err, users, fields) {
            // check if user already exist
            // validate if user exist in our database
            if (err) {
              return res.json({
                ok: false,
                message: "Username already taken.",
                code: HttpStatus.StatusCodes.BAD_REQUEST,
                Text: err.message,
              });
            }
            res.json({
              ok: true,
              message: "Register success.",
              code: HttpStatus.StatusCodes.OK,
            });
          }
        );
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      error: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

//Api Login User
app.post("/login", jsonParser, function (req, res, next) {
  try {
    const { username, password } = req.body;
    if (!(username && password)) {
      return res.json({
        ok: false,
        message: "Please complete the information(login).",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "SELECT * FROM `users` WHERE  username = ?",
        [username],
        function (err, users, fields) {
          if (err) {
            return res.json({
              ok: false,
              message: err,
              code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
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
                  user_id: users[0].user_id,
                  username: users[0].username,
                },
                secret,
                {
                  expiresIn: "1h",
                }
              );
              return res.json({
                ok: true,
                message: "login success.",
                token,
                code: HttpStatus.StatusCodes.OK,
              });
            } else {
              return res.json({
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
    return res.json({
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
    return res.json({
      ok: true,
      message: "success.",
      decoded,
      code: HttpStatus.StatusCodes.OK,
    });
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

// get users
app.get("/users", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT `user_id`, `username`, `first_name`, `last_name`, `birthday`, `gender` FROM `users`",
    (err, result, fields) => {
      if (err) throw err;
      res.json({
        ok: true,
        data: result,
      });
    }
  );
});

// API get users by  user_id
app.get("/user/:userId", jsonParser, function (req, res, next) {
  try {
    var userId = req.params.userId;
    if (userId) {
      connection.execute(
        "SELECT `user_id`, `username`, `first_name`, `last_name`, `gender`, `birthday`, TIMESTAMPDIFF(year,birthday,CURRENT_DATE) AS year FROM users WHERE user_id = ?",
        [userId],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "User information not found(1)",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "User information not found(2)",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (err) {
    // thow message error (command)
    console.log(err);
    return res.json({
      ok: false,
      message: err.message,
      code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
    });
  }
});
// API get users by name
app.get("/username/:userName", jsonParser, function (req, res, next) {
  try {
    var userName = req.params.userName;
    if (userName) {
      connection.execute(
        "SELECT `user_id`, `username`, `first_name`, `last_name`, `birthday` FROM `users` WHERE username = ?",
        [userName],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json({
              ok: true,
              result,
              code: HttpStatus.StatusCodes.OK,
            });
          } else {
            return res.json({
              ok: false,
              message: "User not found(1) ",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "User not found(2) ",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// update Name
app.put("/user/:userId", jsonParser, (req, res) => {
  try {
    const { first_name, last_name } = req.body;
    const userId = req.params.userId;
    if(!first_name && !last_name || !first_name || !last_name){
      res.json({
        ok: false,
        message: "1Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    }
    else{
      connection.execute(
        "UPDATE `users` SET `first_name`= ? ,`last_name`= ? WHERE user_id = ?",
        [first_name, last_name, userId],
        (err, result) => {
          if (err) throw err;
          return res.json({
            ok: true,
            message: "Update Name success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    // } else {
    //   return res.json({
    //     ok: false,
    //     message: "Service Unavailable ",
    //     code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
    //   });
     }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//blood sugar levels
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
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//get blood sugar levels of year by user_id
app.get("/year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    if (userId) {
      connection.execute(
        "SELECT YEAR(`blood_time`) AS year FROM blood WHERE user_id = ? GROUP BY year",
        [userId],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels.",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

//get blood sugar by user_id
app.get("/blood/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    if (userId) {
      connection.execute(
        "SELECT * FROM `blood` WHERE user_id = ?",
        [userId],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json({
              ok: true,
              data: result,
              code: HttpStatus.StatusCodes.OK,
            });
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels.",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// get year by user_id
app.get("/blood/year/:userId",jsonParser,(req,res) =>{
 try {
   const userId = req.params.userId;
   if(userId){
     connection.execute("SELECT YEAR(`blood_time`)AS YEAR FROM `blood` WHERE `user_id` = ? GROUP BY YEAR(`blood_time`)"
     ,[userId],
     (err,result)=>{
       if(err) throw err;
       if(result && result[0]){
         res.json(result);
       }else{
         res.json({
           ok:false,
           message:"Not found Year",
           code: HttpStatus.StatusCodes.BAD_REQUEST
           
         })
       }
     })
   }
 } catch (error) {
  console.log(error);
  return res.json({
    ok: false,
    message: error.message,
    code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
  });
 }
})
//Get average monthly blood sugar by year user_id
app.get("/blood/avg/:year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const year = req.params.year;
    if (userId && year) {
      connection.execute(
        "SELECT YEAR(`blood_time`) AS year ,  MONTHNAME(`blood_time`) as month, AVG(`blood_level`) as average_blood   FROM blood   WHERE user_id = ? and YEAR(`blood_time`) = ?  GROUP BY MONTH(`blood_time`);",
        [userId, year],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels .",
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//
app.get("/blood/sum/:year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const year = req.params.year;
    if (userId && year) {
      connection.execute(
        "SELECT `blood_id`, `blood_time`,MONTHNAME(`blood_time`) as month,`blood_level`, `note`, `user_id` FROM `blood` WHERE user_id = ? and YEAR(`blood_time`) = ? ORDER BY `month`",
        [userId, year],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels .",
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

// Get the average blood sugar for each year by user_id
app.get("/blood/avgyear/:year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const year = req.params.year;
    if (userId && year) {
      connection.execute(
        "SELECT YEAR(`blood_time`) AS year , AVG(`blood_level`) as average_blood   FROM blood    WHERE user_id = ? and YEAR(`blood_time`) = ?  ",
        [userId, year],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels .",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// Get the average blood sugar for each year by user_id
app.get("/blood/desc/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    if (userId) {
      connection.execute(
        "SELECT `blood_level` FROM `blood`WHERE user_id = ?  ORDER BY `blood`.`blood_id` DESC   LIMIT 1;        ",
        [userId],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels Uer .",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// add blood sugar
app.post("/blood/:userId", jsonParser, function (req, res) {
  try {
    const { blood_level, blood_time, note } = req.body;
    const userId = req.params.userId;
    if (!(blood_level && blood_time && userId && note)) {
      res.json({
        ok: false,
        message: "1Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "INSERT INTO `blood`( `blood_level`,blood_time, `note`, `user_id`) VALUES (?,?,?,?)",
        [blood_level, blood_time, note, userId],
        (err, users, fields) => {
          if (err){
            return res.json({
              ok: false,
              message: "Please complete the information.",
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
         
          return res.send({
            ok: true,
            message: "add blood sugar success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// update blood
app.put("/blood/:bloodId", jsonParser, function (req, res) {
  try {
    const { blood_level} = req.body;
    const bloodId = req.params.bloodId;
    if (!(blood_level)) {
      res.json({
        ok: false,
        message: "1Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "UPDATE `blood` SET `blood_level` = ? WHERE `blood`.`blood_id` = ?;",
        [blood_level, bloodId],
        (err, users, fields) => {
          if (err){
            return res.json({
              ok: false,
              message: "Please complete the information.",
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
         
          return res.send({
            ok: true,
            message: "update blood sugar success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//Medication
//get medication all
app.get("/medications", jsonParser, (req, res) => {
  try {
    connection.execute(
      "SELECT * FROM `medication_warehouse`",
      (err, result) => {
        if (err) throw err;
        return res.json(result);
      }
    );
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// get medication by user_id
app.get("/medication/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    if (userId) {
      connection.execute(
        "SELECT `medication_id`, `medication_name`, `medication_amount`, `medication_time`, `time`, `note` FROM `medication_warehouse` WHERE `user_id` = ?",
        [userId],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found Medication .",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found Medication .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// get medication by user_id and medication_id
app.get("/medication/:userId/:medicationId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const medicationId = req.params.medicationId;
    if (userId && medicationId) {
      connection.execute(
        "SELECT `medication_id`, `medication_name`, `medication_amount`, `medication_time`, `time`, `note`, `user_id` FROM `medication_warehouse` WHERE `user_id` = ? AND `medication_id` = ?",
        [userId, medicationId],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found Medication .",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found Medication .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// add medication
app.post("/medication/:userId", jsonParser, function (req, res) {
  try {
    const { medication_name, medication_amount, medication_time, note } =
      req.body;
    const userId = req.params.userId;
    if (!(medication_name && medication_amount && medication_time && note)) {
      res.json({
        ok: false,
        message: "Please complete the information(medication).",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "INSERT INTO `medication_warehouse`( `medication_name`, `medication_amount`, `medication_time`,  `note`, `user_id`) VALUES (?,?,?,?,?)",
        [medication_name, medication_amount, medication_time, note, userId],
        (err, users, fields) => {
          if (err) throw err;
          return res.json({
            ok: true,
            message: "add Medication success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

// update Medication
app.put("/medication/:medicationId", jsonParser, (req, res) => {
  try {
    const { medication_name, medication_amount, medication_time, note } =
      req.body;
    const medicationId = req.params.medicationId;
    if(medicationId){
      connection.execute(
        "UPDATE `medication_warehouse` SET `medication_name` = ?, `medication_amount` = ?, `medication_time` = ?, `note` = ? WHERE `medication_warehouse`.`medication_id` = ?;",
        [medication_name, medication_amount, medication_time, note, medicationId],
        (err, result, next) => {
          if (err) throw err;
          return res.json({
            ok: true,
            message: "seccess1",
            code: HttpStatus.StatusCodes.OK,
          });
        
        }
      );
    }else{
      return res.json({
        ok: false,
        message: "Service Unavailable ",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//delete Medication
app.delete("/medication/:medicationId", jsonParser, (req, res) => {
  try {
    const medicationId = req.params.medicationId;
    if(medicationId){
      connection.execute(
        "DELETE FROM `medication_warehouse` WHERE `medication_id` = ?",
        [medicationId],
        (err, result) => {
          if (err) throw err;
          res.json({
            ok: true,
            message: "delete Medication success",
            code: HttpStatus.StatusCodes.OK,
          });
         }
      );
    }else{
      return res.json({
        ok: false,
        message: "Service Unavailable ",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

// get food

app.get("/foods", jsonParser, (req, res) => {
  try {
    connection.execute("SELECT * FROM `food`", (err, result) => {
      if (err) throw err;
      if(result &&result[0]){
        return res.json(result);
      }else{
        return res.json({
          ok: false,
          message: "No found food .",
          code: HttpStatus.StatusCodes.NOT_FOUND,
        });
      }
    });
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});

app.post("/food", jsonParser, (req, res) => {
  try {
    const { food_name, calorie } = req.body;
    if (!(food_name && calorie)) {
      res.json({
        ok: false,
        message: "1Please complete the information.",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "INSERT INTO `food`( `food_name`, `calorie`) VALUES (?,?)",
        [food_name, calorie],
        (err, result) => {
          if (err) throw err;
          return res.json({
            ok: true,
            message: "success",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//
app.post("/foodDetail/:userId/:foodId", jsonParser, function (req, res) {
  try {
    const userId = req.params.userId;
    const foodId = req.params.foodId
    if (!(userId  && foodId )) {
      res.json({
        ok: false,
        message: "Please complete the information(medication).",
        code: HttpStatus.StatusCodes.BAD_REQUEST,
      });
    } else {
      connection.execute(
        "INSERT INTO `food_detail` ( `user_id`, `food_id`) VALUES (?,?) ",
        [userId,foodId],
        (err, users, fields) => {
          if (err) throw err;
          return res.json({
            ok: true,
            message: "add food datail success.",
            code: HttpStatus.StatusCodes.OK,
          });
        }
      );
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
// get Year by user_id 
app.get("/food/year/:userId",jsonParser,(req,res) =>{
  try {
    const userId = req.params.userId;
    if(userId){
      connection.execute("SELECT YEAR(`date`)AS YEAR FROM `food_detail` WHERE `user_id` = ? GROUP BY YEAR(`date`)"
      ,[userId],
      (err,result)=>{
        if(err) throw err;
        if(result && result[0]){
          res.json(result);
        }else{
          res.json({
            ok:false,
            message:"Not found Year",
            code: HttpStatus.StatusCodes.BAD_REQUEST
            
          })
        }
      })
    }
  } catch (error) {
   console.log(error);
   return res.json({
     ok: false,
     message: error.message,
     code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
   });
  }
 });
 // get Year  avg by user_id 
//  app.get("/food/avg/:year/:userId", jsonParser, (req, res) => {
//   try {
//     const userId = req.params.userId;
//     const year = req.params.year;
//     if (userId && year) {
//       connection.execute(
//         "SELECT YEAR(`date`) AS year ,  MONTHNAME(`date`) as month, AVG(`calorie`) as calorie   FROM food_detail   WHERE user_id = ? and YEAR(`date`) = ?  GROUP BY MONTH(`date`)",
//         [userId, year],
//         (err, result) => {
//           if (err) throw err;
//           if (result && result[0]) {
//             return res.json(result);
//           } else {
//             return res.json({
//               ok: false,
//               message: "No found blood sugar levels .",
//               code: HttpStatus.StatusCodes.BAD_REQUEST,
//             });
//           }
//         }
//       );
//     } else {
//       return res.json({
//         ok: false,
//         message: "No found blood sugar levels .",
//         code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
//       });
//     }
//   } catch (error) {
//     console.log(error);
//     return res.json({
//       ok: false,
//       message: error.message,
//       code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
//     });
//   }
// });
// Get the average food for each year by user_id
app.get("/food/avgyear/:year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const year = req.params.year;
    if (userId && year) {
      connection.execute(
        "SELECT YEAR(food_detail.date) AS YEAR , AVG(food.calorie) AS average_calorie   FROM food_detail  LEFT JOIN  food ON food_detail.food_id=food.food_id WHERE user_id = ? and YEAR(food_detail.date) = ?    ",
        [userId, year],
        (err, result, fields) => {
          if (err) throw err;
          if (result && result[0]) {
            res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found calorie levels .",
              code: HttpStatus.StatusCodes.NOT_FOUND,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
 // get Year  avg by user_id  and join

app.get("/food/avg/:year/:userId", jsonParser, (req, res) => {
  try {
    const userId = req.params.userId;
    const year = req.params.year;
    if (userId && year) {
      connection.execute(
        "SELECT YEAR(food_detail.date) AS YEAR, MONTHNAME(food_detail.date) AS MONTH, AVG(food.calorie)FROM food_detail LEFT JOIN  food ON food_detail.food_id=food.food_id WHERE user_id = ? and YEAR(food_detail.date) = ? GROUP BY MONTH(food_detail.date)",
        [userId, year],
        (err, result) => {
          if (err) throw err;
          if (result && result[0]) {
            return res.json(result);
          } else {
            return res.json({
              ok: false,
              message: "No found blood sugar levels .",
              code: HttpStatus.StatusCodes.BAD_REQUEST,
            });
          }
        }
      );
    } else {
      return res.json({
        ok: false,
        message: "No found blood sugar levels .",
        code: HttpStatus.StatusCodes.SERVICE_UNAVAILABLE,
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      ok: false,
      message: error.message,
      code: HttpStatus.StatusCodes.INTERNAL_SERVER_ERROR,
    });
  }
});
//TEST POST food detail with param

app.listen(process.env.APP_PORT,  () => {
  console.log("web server is running on port ", process.env.APP_PORT);
});
