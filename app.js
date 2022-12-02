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

app.use(bodyParser.urlencoded({ extended: false }))
app.use(cors())

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'dsme'
  });

app.get('/', function (req, res, next) {
  res.json({msg: 'This is CORS-enabled for all origins!'})
})

app.post('/register',jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        connection.execute(
            'INSERT INTO users(username, password, first_name, last_name, birthday) VALUES (?,?,?,?,?)',
            [req.body.username, hash, req.body.first_name, req.body.last_name, req.body.birthday],
            function(err, results, fields) {
              if(err){
                res.json({status:'error', message:err});
                return
              }
              res.json({status:'ok'})
            }
          );
    });

    
  })

  app.post('/login', function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE username = ?',
        [req.body.username],
        function(err, users, fields) {
          if(err){res.json({status:'error', message:err});  return}
          if(users.length == 0){res.json({status:'error', message:'on found users'}); return}
          bcrypt.compare(req.body.password, users[0], function(err, result) {
            // result == true
            if(result){
                res.json({status:'ok',message:'login success'})
            }else{
                res.json({status:'error',message:'loging failed'})
            }
        });
          res.json({status:'ok'})
        }
      );
  })

app.listen(3000, function () {
  console.log('CORS-enabled web server listening on port 3000')
})