require('dotenv').config();
const mysql = require("mysql2");

const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: process.env.DB_PASSWORD,
    database: "school"
});

connection.connect((err) => {
    if(err){
        console.log(err);
    }
    else{
        console.log("Connected to MySQL");
    }
});

module.exports = connection;