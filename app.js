var express = require('express')
var cors = require('cors')
var bodyParser = require('body-parser')
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'dsme';

var app = express()
var jsonParser = bodyParser.json();

app.use(bodyParser.urlencoded({
  extended: false
}))
app.use(cors())
 //connection database
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'dsme'
});

app.get('/', jsonParser, function (req, res, next) {
  res.json({
    msg: 'This is origins!'
  })
})

// Api Register
app.post('/register', jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    connection.execute(
      'INSERT INTO users(username, password, first_name, last_name, birthday) VALUES (?,?,?,?,?)',
      [req.body.username, hash, req.body.first_name, req.body.last_name, req.body.birthday],
      function (err, results, fields) {
        if (err) {
          return res.status(400).json({message:'Please fill in the information correctly.'})
        }
        return res.status(200).json({message:'Register success'})
        })
      }
    );
  });

//Api Login
app.post('/login', jsonParser, function (req, res, next) {
  connection.execute(
    'SELECT * FROM `users` WHERE  username = ?',
    [req.body.username],
    function (err, users, fields) {
      if (err) {
       
        return res.status(400).json({message:err})
      }
      if (users.length == 0) {
        return res.status(400).json({message:'on found users.'})
      }
      bcrypt.compare(req.body.password, users[0].password, function (err, result) {
        // result == true
        if (result) {
          var token = jwt.sign({
            username: users[0].username
          }, secret, {
            expiresIn: '1y'
          });
          return res.status(200).json({message:'login success.',token})
        } else {
      
          return res.status(400).json({message:'loging failed.'})
        }
      });
    }
  );
})

// Api authen check token
app.post('/authen', jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(' ')[1]
    var decoded = jwt.verify(token, secret);
    return res.status(200).json({message:'success.'})
  } catch(err) {
      return res.status(400).json({message: err.message})
  }

})

app.listen(3000, function () {
  console.log('web server listening on port 3000')
})