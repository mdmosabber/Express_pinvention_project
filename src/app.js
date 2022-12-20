const {readdirSync} = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const cors = require('cors');
const errorHandler = require('./middleware/errorMiddleware');
require("dotenv").config();

const app = express();

//middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));


readdirSync(path.join(__dirname,'routes')).map(routeFile => app.use('/api/v1', require(`./routes/${routeFile}`)));


// 404 error handle
app.use((req,res, next)=> {
    res.status(404).json({message: '4🧡4 Not Found'})
})

app.use(errorHandler)

module.exports = app;