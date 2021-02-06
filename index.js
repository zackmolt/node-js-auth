let crypto = require('crypto');
let uuid = require('uuid');
let express = require('express');
let mysql = require('mysql');
let bparser = require('body-parser');

//CONNECT MYSQL

let con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'firstnode'
});

//PASSWORD ULTIL
var getRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
};

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = getRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

let app = express();
app.use(bparser.json());
app.use(bparser.urlencoded({ extended: true }));

function checkHashPassword(userPass, salt) {
    var passData = sha512(userPass, salt);
    return passData;
}




app.post("/reg/", (req, res, next) => {
    
     /*REQUEST PARAMS
     
     name
     email
     password*/
     
    var postData = req.body;

    var uid = uuid.v4();
    var plaint_pass = postData.password;
    var hash_data = saltHashPassword(plaint_pass);
    var pass = hash_data.passwordHash;
    var salt = hash_data.salt;
    
    var name = postData.name;
    var email = postData.email;
    console.log(name + '\n' + email + '\n' + plaint_pass);

    con.query('SELECT * FROM `user_data` where email=?', [email], function (err, result, fields) {
        con.on('error', function (err) {
            console.log('ERROR ', err);
        });
        if (result && result.length) {
            res.json('User with ' + email + ' email already exist');
        } else {
            con.query('INSERT INTO `user_data`(`unique_id`,`name`,`email`,`encrypted_password`,`salt`,`created_at`,`updated_at`) VALUES(?,?,?,?,?,NOW(),NOW())', [uid, name, email, pass, salt], function (err, result, fields) {
                con.on('error', function (err) {
                    console.log('ERROR ', err);
                    res.json('Register error:', err)
                });

                res.json('REGISTER Successful');

            });
        }
    });
});

app.post("/login/", (req, res, next) => {

    var postData = req.body;

    var pass = postData.password;
    var email = postData.email;

    con.query('SELECT * FROM `user_data` where email=?', [email], function (err, result, fields) {
        con.on('error', function (err) {
            console.log('ERROR ', err);
        });
        if (result && result.length) {
            var salt = result[0].salt;
            var enc_pass = result[0].encrypted_password;
            var hashed_pass = checkHashPassword(pass, salt).passwordHash;
            if (hashed_pass === enc_pass)
                res.end(JSON.stringify(result[0]));
            else
                res.end(JSON.stringify('WRONG Pass'));
        } else {
            res.json('User doesn`t exist');
        }
    });

   
});

//start server
app.listen(3000, () => {
    console.log('RESTFUL running on port 3000');
});