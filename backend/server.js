const express = require('express');
const dotenv = require('dotenv').config();
const { errorHandler } = require('./middleware/errorHandler');
const connectDB = require('./config/db');
const port = process.env.PORT || 5000;

//connect DB
connectDB();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use('/api/goals', require('./routes/goalRoutes'));

app.use(errorHandler);

app.listen(port, () => console.log(`Server started on Port ${port}`));
