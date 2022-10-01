const express = require('express')
const BodyParser = require('body-parser')
const dotenv = require('dotenv').config();
const connectDB = require('./src/config/db');
const userRoutes = require('./src/routes/user')
const { errorHandler } = require('./src/middleware/error');
const port = process.env.PORT || 5000;

connectDB().then(() => {
    const app = express()
    app.use(BodyParser.json())

    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', '*')
        res.setHeader('Access-Control-Allow-Method', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        next()
    })

    // app.use('/api/v1/auth', authRoutes)
    app.use('/api/v1/users', userRoutes)
    app.get('/', (req, res) => res.json('API V1 Mern Stack'));

    app.use(errorHandler);

    app.listen(port, () => console.log(`Server started on port ${port}`));
}).catch((err) => {
    console.log(err, 'Fail')
})

